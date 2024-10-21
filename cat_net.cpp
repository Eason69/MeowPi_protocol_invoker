#include "cat_net.h"

#include <iostream>
#include <thread>

CatNet::CatNet() {
    client.clear_access_channels(websocketpp::log::alevel::all);
    client.clear_error_channels(websocketpp::log::elevel::all);

    client.init_asio();

    client.set_open_handler([this](const websocketpp::connection_hdl& hdl) {
        this->open(hdl);
    });

    client.set_fail_handler([this](const websocketpp::connection_hdl& hdl) {
        this->fail(hdl);
    });

    client.set_close_handler([this](const websocketpp::connection_hdl& hdl) {
        this->close(hdl);
    });
    client.set_message_handler([this](const websocketpp::connection_hdl& hdl,
                                      const websocketpp::client<websocketpp::config::asio_tls_client>::message_ptr& msg) {
        this->message(hdl, msg);
    });

}

CatNet::~CatNet() {
    if (client_thread.joinable()) {
        client_thread.join();
    }
}

CatNet::ErrorCode CatNet::run(const std::string &box_ip, int box_port, const std::string &client_pem, const std::string &client_key, const std::string &ca_pem, int milliseconds) {
    std::string url = "wss://" + box_ip + ":" + std::to_string(box_port);

    asio::const_buffer client_pem_buffer(client_pem.data(), client_pem.size());
    asio::const_buffer client_key_buffer(client_key.data(), client_key.size());
    asio::const_buffer ca_pem_buffer(ca_pem.data(), ca_pem.size());

    client.set_tls_init_handler([client_pem_buffer, client_key_buffer, ca_pem_buffer](const websocketpp::connection_hdl&) {
        std::shared_ptr<asio::ssl::context> ctx = std::make_shared<asio::ssl::context>(asio::ssl::context::tlsv13);
        try {
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::no_tlsv1 |
                             asio::ssl::context::no_tlsv1_1 |
                             asio::ssl::context::no_tlsv1_2);

            ctx->use_certificate_chain(client_pem_buffer);
            ctx->use_private_key(client_key_buffer, websocketpp::lib::asio::ssl::context::pem);
            ctx->add_certificate_authority(ca_pem_buffer);
            ctx->set_verify_callback([](bool preverified, websocketpp::lib::asio::ssl::verify_context &ctx) {
                char subject_name[256];
                X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
                X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
                return preverified;
            });

            ctx->set_verify_mode(websocketpp::lib::asio::ssl::verify_peer);
        } catch (std::exception& e) {

        }
        return ctx;
    });

    try {
        auto start_time = std::chrono::steady_clock::now();
        while (!is_stop) {
            websocketpp::lib::error_code ec;
            websocketpp::client<websocketpp::config::asio_tls_client>::connection_ptr con =
                    client.get_connection(url,ec);
            if (ec) {
                return INIT_FAILED;
            }

            client.connect(con);
            client_thread = std::thread([this]() {
                try {
                    client.run();
                } catch (const std::exception&) {}
            });

            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock);
            if (!connected.load()) {
                if (client_thread.joinable()) {
                    client_thread.join();
                }
                client.reset();
                if (milliseconds != -1) {
                    auto elapsed_time = std::chrono::steady_clock::now() - start_time;
                    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time).count();
                    if (elapsed_ms >= milliseconds) {
                        return INIT_FAILED;
                    }
                }
            } else {
                break;
            }

        }
        is_init = true;
        return SUCCESS;
    }
    catch (const std::exception &e) {
        std::cerr << "Socket error: " << e.what() << std::endl;
        return INIT_FAILED;
    }
}

void CatNet::stop() {
    is_stop = true;
    if (is_init) {
        client.stop();
        if (client_thread.joinable()) {
            client_thread.join();
        }
    }
}

CatNet::ErrorCode CatNet::monitor() {
    if (!is_init) {
        return INIT_FAILED;
    }
    if (is_monitor) {
        return MONITOR_OPEN;
    }
    CmdData cmd_data {
            .cmd = CMD_MONITOR,
            .options = 0x01
    };
    if (sendCmd(cmd_data) == SUCCESS) {
        is_monitor = true;
        return SUCCESS;
    }
    return SEND_FAILED;
}

CatNet::ErrorCode CatNet::closeMonitor() {
    if (is_monitor) {
        CmdData cmd_data {
                .cmd = CMD_MONITOR,
                .options = 0x00
        };
        if (sendCmd(cmd_data) == SUCCESS) {
            is_monitor = false;
            return SUCCESS;
        }
        return SEND_FAILED;
    }
    return MONITOR_CLOSE;
}

void CatNet::open(const websocketpp::connection_hdl& hdl) {
    connected.store(true);
    cv.notify_all();
    server_hdl = hdl;
}

void CatNet::fail(const websocketpp::connection_hdl& hdl) {
    connected.store(false);
    cv.notify_all();
}

void CatNet::close(const websocketpp::connection_hdl& hdl) {
    if (hdl.lock() == server_hdl.lock()) {
        connected.store(false);
    }
}

void CatNet::message(const websocketpp::connection_hdl&,
             const websocketpp::client<websocketpp::config::asio_tls_client>::message_ptr& msg) {
    std::string payload = msg->get_payload();
    const auto *buf = reinterpret_cast<const unsigned char *>(payload.c_str());

    HidData hid_data{};
    if (payload.size() >= sizeof(HidData)) {
        std::memcpy(&hid_data, buf, sizeof(HidData));
    } else {
        return;
    }

    mouse_state.updateKeyState(hid_data.mouse_data.code, hid_data.mouse_data.value);
    mouse_state.updateAxis(hid_data.mouse_data.mouseEvent.x, hid_data.mouse_data.mouseEvent.y, hid_data.mouse_data.mouseEvent.wheel);

    keyboard_state.updateKeyState(hid_data.keyboard_data.code, hid_data.keyboard_data.value);
    lock_state = hid_data.keyboard_data.lock;
}

CatNet::ErrorCode CatNet::sendCmd(CmdData data) {
    unsigned char cmd_buf[sizeof(CmdData)];
    memcpy(cmd_buf, &data, sizeof(CmdData));
    websocketpp::lib::error_code ec;
    client.send(server_hdl, cmd_buf, sizeof(CmdData),websocketpp::frame::opcode::binary, ec);
    if (ec) {
        return SEND_FAILED;
    }
    return SUCCESS;
}

CatNet::ErrorCode CatNet::mouseMove(int16_t x, int16_t y) {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_MOUSE_MOVE
    };
    cmd_data.value1 = x;
    cmd_data.value2 = y;
    return sendCmd(cmd_data);
}

CatNet::ErrorCode CatNet::mouseMoveAuto(int16_t x, int16_t y, int16_t ms) {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_MOUSE_AUTO_MOVE
    };
    cmd_data.options = ms;
    cmd_data.value1 = x;
    cmd_data.value2 = y;
    return sendCmd(cmd_data);
}

CatNet::ErrorCode CatNet::mouseButton(uint16_t code, uint16_t value) {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_MOUSE_BUTTON
    };
    cmd_data.options = code;
    cmd_data.value1 = static_cast<int16_t>(value);
    return sendCmd(cmd_data);
}

CatNet::ErrorCode CatNet::tapMouseButton(uint16_t code, int16_t ms) {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_MOUSE_BUTTON
    };
    cmd_data.options = code;
    cmd_data.value1 = 1;
    sendCmd(cmd_data);
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    cmd_data.value1 = 0;
    return sendCmd(cmd_data);
}

CatNet::ErrorCode CatNet::keyboardButton(uint16_t code, uint16_t value) {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_KEYBOARD_BUTTON
    };
    cmd_data.options = code;
    cmd_data.value1 = static_cast<int16_t>(value);
    return sendCmd(cmd_data);
}

CatNet::ErrorCode CatNet::tapKeyboardButton(uint16_t code, int16_t ms) {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_KEYBOARD_BUTTON
    };
    cmd_data.options = code;
    cmd_data.value1 = 1;
    sendCmd(cmd_data);
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    cmd_data.value1 = 0;
    return sendCmd(cmd_data);
}

bool CatNet::isMousePressed(uint16_t code) {
    if (!is_monitor) {
        return false;
    }
    return mouse_state.isKeyPressed(code);
}

bool CatNet::isKeyboardPressed(uint16_t code) {
    if (!is_monitor) {
        return false;
    }
    return keyboard_state.isKeyPressed(code);
}

bool CatNet::isLockKeyPressed(uint16_t code) const {
    if (!is_monitor) {
        return false;
    }
    return (lock_state & code) != 0;
}

CatNet::ErrorCode CatNet::blockedMouse(uint16_t code, uint16_t value) {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_BLOCKED
    };
    cmd_data.options = 0x01;
    cmd_data.value1 = static_cast<int16_t>(code);
    cmd_data.value2 = static_cast<int16_t>(value);
    return sendCmd(cmd_data);
}

CatNet::ErrorCode CatNet::blockedKeyboard(uint16_t code, uint16_t value) {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_BLOCKED
    };
    cmd_data.options = 0x02;
    cmd_data.value1 = static_cast<int16_t>(code);
    cmd_data.value2 = static_cast<int16_t>(value);
    return sendCmd(cmd_data);
}

CatNet::ErrorCode CatNet::unblockedMouseAll() {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_UNBLOCKED_MOUSE_ALL
    };
    return sendCmd(cmd_data);
}

CatNet::ErrorCode CatNet::unblockedKeyboardAll() {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_UNBLOCKED_KEYBOARD_ALL
    };
    return sendCmd(cmd_data);
}