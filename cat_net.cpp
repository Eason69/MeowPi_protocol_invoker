#include "cat_net.h"

#include <iostream>
#include <thread>

CatNet::CatNet() : send_socket(send_io_context) {
}

CatNet::ErrorCode CatNet::init(const std::string& box_ip, int box_port, const std::string& uuid, int milliseconds) {
    m_key = expandTo16Bytes(uuid);
    try {
        auto box_endpoint = asio::ip::tcp::endpoint(asio::ip::address::from_string(box_ip), box_port);
        asio::steady_timer timer(send_io_context);
        bool timed_out = false;

        timer.expires_after(std::chrono::milliseconds(milliseconds));
        timer.async_wait([&](const asio::error_code& error) {
            if (!error) {
                timed_out = true;
                send_socket.close(); // Cancel the connection
            }
        });

        asio::error_code ec;
        send_socket.async_connect(box_endpoint, [&](const asio::error_code& error) {
            ec = error;
        });

        send_io_context.run();

        if (timed_out) {
            return SOCKET_TIMEOUT;
        }

        startReceive();
        read_io_context_thread = std::thread([this] { send_io_context.run(); });
        is_init = true;
        return SUCCESS;
    }
    catch (const asio::system_error& ) {
        return SOCKET_FAILED;
    }
}

void CatNet::unInit() {
    send_io_context.stop();
    if (read_io_context_thread.joinable()) {
        read_io_context_thread.join();
    }
    if (send_socket.is_open()) {
        send_socket.close();
    }
    send_io_context.restart();
}

CatNet::ErrorCode CatNet::monitor() {
    if (!is_init) {
        return INIT_FAILED;
    }
    if (is_monitor) {
        return MONITOR_OPEN;
    }
    try {
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
    catch (const asio::system_error& e) {
        std::cerr << "Socket error: " << e.what() << std::endl;
        return SOCKET_FAILED;
    }
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

void CatNet::hidHandle(std::size_t receive_len) {
    if (receive_len < AES_BLOCK_SIZE) {
        return;
    }
    const auto* encrypt_buf = reinterpret_cast<const unsigned char*>(buffer.data());
    unsigned char buf[1024];
    int len = aes128CBCDecrypt(encrypt_buf, static_cast<int>(receive_len), m_key, buf);
    HidData hid_data{};
    if (len >= sizeof(HidData)) {
        std::memcpy(&hid_data, buf, sizeof(HidData));
    } else {
        return;
    }

    mouse_state.updateKeyState(hid_data.mouse_data.code, hid_data.mouse_data.value);
    mouse_state.updateAxis(hid_data.mouse_data.mouseEvent.x, hid_data.mouse_data.mouseEvent.y, hid_data.mouse_data.mouseEvent.wheel);

    keyboard_state.updateKeyState(hid_data.keyboard_data.code, hid_data.keyboard_data.value);
    lock_state = hid_data.keyboard_data.lock;
}

void CatNet::startReceive() {
    send_socket.async_receive(
            asio::buffer(buffer),
            [this](asio::error_code, std::size_t len) {
                if (len > 0) {
                    hidHandle(len);
                }
                startReceive();
            });
}

CatNet::ErrorCode CatNet::receiveAck(int milliseconds) {
    std::array<char, 1024> buf{};
    int sock_fd = static_cast<int>(send_socket.native_handle());

    timeval timeout{};
    timeval *timeout_ptr = nullptr;

    if (milliseconds != -1) {
        timeout.tv_sec = milliseconds / 1000;
        timeout.tv_usec = (milliseconds % 1000) * 1000;
        timeout_ptr = &timeout;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock_fd, &read_fds);
    int result = select(sock_fd + 1, &read_fds, nullptr, nullptr, timeout_ptr);
    if (result > 0) {
        size_t len = send_socket.receive(asio::buffer(buf));
        if (len > 0) {
            const auto *encrypt_buf = reinterpret_cast<const unsigned char *>(buf.data());
            unsigned char decrypt_buf[1024];
            int decrypt_len = aes128CBCDecrypt(encrypt_buf, static_cast<int>(len), m_key, decrypt_buf);
            if (decrypt_len > 0) {
                return SUCCESS;
            }
        }
    } else if (result == 0) {
        return RECEIVE_TIMEOUT;
    }
    return RECEIVE_FAILED;
}

CatNet::ErrorCode CatNet::sendCmd(CmdData data) {
    if (!send_socket.is_open()) {
        return SOCKET_FAILED;
    }
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    unsigned char cmd_buf[sizeof(CmdData)];
    memcpy(cmd_buf, &data, sizeof(CmdData));

    unsigned char encrypt_buf[1024];
    int encrypt_len = aes128CBCEncrypt(cmd_buf, sizeof(CmdData), m_key, iv, encrypt_buf);

    if (encrypt_len <= 0) {
        return ENCRYPTION_FAILED;
    }

    try {
        asio::write(send_socket, asio::buffer(encrypt_buf, encrypt_len));
        return SUCCESS;
    } catch (asio::system_error &) {
        return SEND_FAILED;
    }
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
    sendCmd(cmd_data);
    return receiveAck(ms + 500);
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

CatNet::ErrorCode  CatNet::blockedMouse(uint16_t code, uint16_t value) {
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

CatNet::ErrorCode  CatNet::blockedKeyboard(uint16_t code, uint16_t value) {
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

CatNet::ErrorCode  CatNet::unblockedMouseAll() {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_UNBLOCKED_MOUSE_ALL
    };
    return sendCmd(cmd_data);
}

CatNet::ErrorCode  CatNet::unblockedKeyboardAll() {
    if (!is_init) {
        return INIT_FAILED;
    }
    static CmdData cmd_data{
            .cmd = CMD_UNBLOCKED_KEYBOARD_ALL
    };
    return sendCmd(cmd_data);
}