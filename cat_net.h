#ifndef CAT_NET_H
#define CAT_NET_H

#include <asio.hpp>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "input-event-codes.h"

class CatNet {
private:
    static constexpr uint8_t CMD_CONNECT                 = 0x01;
    static constexpr uint8_t CMD_MONITOR                 = 0x02;
    static constexpr uint8_t CMD_MOUSE_BUTTON            = 0x03;
    static constexpr uint8_t CMD_KEYBOARD_BUTTON         = 0x04;
    static constexpr uint8_t CMD_BLOCKED                 = 0x05;
    static constexpr uint8_t CMD_UNBLOCKED_MOUSE_ALL     = 0x06;
    static constexpr uint8_t CMD_UNBLOCKED_KEYBOARD_ALL  = 0x07;
    static constexpr uint8_t CMD_MOUSE_MOVE              = 0x08;
    static constexpr uint8_t CMD_MOUSE_AUTO_MOVE         = 0x09;

#pragma pack(1)
    struct CmdData {
        uint8_t cmd;
        uint16_t options;
        int16_t value1;
        int16_t value2;
    };

    struct MouseEvent {
        int16_t x;
        int16_t y;
        int16_t wheel;
    };

    struct MouseData {
        uint16_t code;
        uint16_t value;
        MouseEvent mouseEvent;
    };

    struct KeyboardData {
        uint16_t code;
        uint16_t value;
        uint8_t lock;
    };

    struct HidData {
        MouseData mouse_data;
        KeyboardData keyboard_data;
    };
#pragma pack()

    struct KeyStateManager {
        std::bitset<KEY_CNT> keyStateBitset;

        KeyStateManager() {
            keyStateBitset.reset();
        }

        void updateKeyState(uint16_t key, bool isPressed) {
            if (key <= KEY_CNT) {
                keyStateBitset.set(key, isPressed);
            }
        }

        [[nodiscard]] bool isKeyPressed(uint16_t key) const {
            if (key <= KEY_CNT) {
                return keyStateBitset.test(key);
            }
            return false;
        }
    };

    struct MouseStateManager {
        std::bitset<KEY_CNT> keyStateBitset;
        MouseEvent mouseEvent{};

        MouseStateManager() {
            keyStateBitset.reset();
        }

        void updateAxis(int16_t x, int16_t y, int16_t wheel) {
            mouseEvent.x = x;
            mouseEvent.y = y;
            mouseEvent.wheel = wheel;
        }

        MouseEvent &getMouseEvent() {
            return mouseEvent;
        }

        void updateKeyState(uint16_t key, bool isPressed) {
            if (key <= KEY_CNT) {
                keyStateBitset.set(key, isPressed);
            }
        }

        [[nodiscard]] bool isKeyPressed(uint16_t key) const {
            if (key <= KEY_CNT) {
                return keyStateBitset.test(key);
            }
            return false;
        }
    };
public:
    /**
     * @brief 表示NET操作的错误代码
     *
     * 枚举类型用于描述不同类型的网络操作错误及其状态码。
     */
    enum ErrorCode {
        /**
         * @brief 操作成功
         *
         * 表示操作已成功完成，没有发生任何错误。
         */
        SUCCESS = 0,

        /**
         * @brief 解密失败
         *
         * 表示在解密过程中发生错误。
         */
        DECRYPTION_FAILED = 100,

        /**
         * @brief 加密失败
         *
         * 表示在加密过程中发生错误。
         */
        ENCRYPTION_FAILED = 101,

        /**
         * @brief 发送失败
         *
         * 表示在数据发送过程中发生错误。
         */
        SEND_FAILED = 102,

        /**
         * @brief 接收失败
         *
         * 表示在数据接收过程中发生错误。
         */
        RECEIVE_FAILED = 103,

        /**
         * @brief 接收超时
         *
         * 表示在规定时间内没有接收到数据，发生超时错误。
         */
        RECEIVE_TIMEOUT = 104,

        /**
         * @brief 初始化失败
         *
         * 表示系统或网络模块初始化失败。
         */
        INIT_FAILED = 300,

        /**
         * @brief 监听未开启
         *
         * 表示监视器没有正确启动。
         */
        MONITOR_CLOSE = 301,

        /**
         * @brief 监听已开启
         *
         * 表示监视器已经成功开启。
         */
        MONITOR_OPEN = 302,

        /**
         * @brief socket 错误
         *
         * 表示在 socket 操作过程中发生错误。
         */
        SOCKET_FAILED = 500,

        /**
         * @brief socket 超时
         *
         * 表示 socket 操作超时。
         */
        SOCKET_TIMEOUT = 501
    };

    CatNet();

    /**
     * 初始化函数 超时请检查UUID是否正确
     * @param box_ip 盒子ip
     * @param box_port 盒子端口
     * @param uuid 盒子uuid
     * @param seconds 初始化盒子响应ACK超时时间 单位ms -1为无限等待
     * @return ErrorCode
     */
    ErrorCode init(const std::string& box_ip, int box_port, const std::string& uuid, int milliseconds = 5000);

    /**
     * 开启鼠键事件监听
     * @param server_port 本机监听的端口
     * @param seconds 初始化盒子响应ACK超时时间 单位ms -1为无限等待
     * @return ErrorCode
     */
    ErrorCode monitor(int server_port, int milliseconds = 5000);

    /**
     * 关闭键鼠事件监听
     */
    void closeMonitor();

    // 控制部分
    /**
     * 鼠标移动
     * @param x 正值向右
     * @param y 正值向下
     * @return ErrorCode
     */
    CatNet::ErrorCode mouseMove(int16_t x, int16_t y);

    /**
     * 鼠标算法优化移动
     * @param x 正值向下
     * @param y 正值向右
     * @param ms 移动时间
     * @return ErrorCode
     */
    CatNet::ErrorCode mouseMoveAuto(int16_t x, int16_t y, int16_t ms);

    /**
     * 鼠标按键触发
     * @param code 按键值，参考event-codes
     * @param value 按下1 释放0
     * @return ErrorCode
     */
    CatNet::ErrorCode mouseButton(uint16_t code, uint16_t value);

    /**
     * 鼠标按下多少ms后释放
     * @param code 按键值，参考event-codes
     * @param ms 毫秒
     * @return ErrorCode
     */
    CatNet::ErrorCode tapMouseButton(uint16_t code, int16_t ms);

    /**
     * 键盘按键触发
     * @param code 按键值，参考event-codes
     * @param value 按下1 释放0
     * @return ErrorCode
     */
    CatNet::ErrorCode keyboardButton(uint16_t code, uint16_t value);

    /**
     * 键盘按键按下多少ms后释放
     * @param code 按键值，参考event-codes
     * @param ms 毫秒
     * @return ErrorCode
     */
    CatNet::ErrorCode tapKeyboardButton(uint16_t code, int16_t ms);

    // 监测部分
    /**
     * 监测鼠标某个键是否按下
     * @param code 按键值，参考event-codes
     * @return 按下true 释放false
     */
    bool isMousePressed(uint16_t code);

    /**
     * 监测键盘按键某个键是否按下
     * @param code 按键值，参考event-codes
     * @return 按下true 释放false
     */
    bool isKeyboardPressed(uint16_t code);

    /**
     * 监测锁定键是否按下
     * @param code NumLock CapsLock ScrLOCK
     * @return 按下true 释放false
     */
    bool isLockKeyPressed(uint16_t code) const;

    // 屏蔽部分
    /**
     * 屏蔽鼠标某个键
     * @param code  按键值，参考event-codes
     * @param value  屏蔽1 解除屏蔽0
     * @return ErrorCode
     */
    CatNet::ErrorCode blockedMouse(uint16_t code, uint16_t value);

    /**
     * 屏蔽键盘某个键
     * @param code  按键值，参考event-codes
     * @param value  屏蔽1 解除屏蔽0
     * @return ErrorCode
     */
    CatNet::ErrorCode blockedKeyboard(uint16_t code, uint16_t value);

    /**
     * 解除鼠标所有屏蔽按键
     * @return ErrorCode
     */
    CatNet::ErrorCode unblockedMouseAll();

    /**
     * 解除键盘所有屏蔽按键
     * @return ErrorCode
     */
    CatNet::ErrorCode unblockedKeyboardAll();

private:
    bool is_init = false;
    bool is_monitor = false;
    asio::io_context read_io_context;
    asio::ip::udp::socket read_socket;
    asio::ip::udp::endpoint server_endpoint;
    asio::io_context send_io_context;
    asio::ip::udp::socket send_socket;
    asio::ip::udp::endpoint box_endpoint;
    std::thread read_io_context_thread;
    std::array<char, 1024> buffer{};

    const unsigned char *m_key{};

    MouseStateManager mouse_state;
    KeyStateManager keyboard_state;
    uint8_t lock_state{};

private:
    void startReceive();

    ErrorCode sendCmd(CmdData data);

    void hidHandle(std::size_t receive_len);

    ErrorCode receiveAck(int milliseconds);

    static int aes128CBCEncrypt(const unsigned char *buf, int buf_len, const unsigned char *key, const unsigned char *iv,
                                unsigned char *encrypt_buf) {
        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;
        memcpy(encrypt_buf, iv, AES_BLOCK_SIZE);

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return -1;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if (EVP_EncryptUpdate(ctx, encrypt_buf + AES_BLOCK_SIZE, &len, buf, buf_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, encrypt_buf + AES_BLOCK_SIZE + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        ciphertext_len += len;

        ciphertext_len += AES_BLOCK_SIZE;

        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
    }

    static int aes128CBCDecrypt(const unsigned char *encrypt_buf, int encrypt_buf_len, const unsigned char *key,
                                unsigned char *decrypt_buf) {
        EVP_CIPHER_CTX *ctx;

        int len;
        int decryptBufLen;

        unsigned char iv[AES_BLOCK_SIZE];
        memcpy(iv, encrypt_buf, AES_BLOCK_SIZE);

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return -1;
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if (EVP_DecryptUpdate(ctx, decrypt_buf, &len, encrypt_buf + AES_BLOCK_SIZE, encrypt_buf_len - AES_BLOCK_SIZE) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        decryptBufLen = len;

        if (EVP_DecryptFinal_ex(ctx, decrypt_buf + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        decryptBufLen += len;

        EVP_CIPHER_CTX_free(ctx);

        return decryptBufLen;
    }

    static unsigned char *expandTo16Bytes(const std::string& cat_uuid) {
        auto uuid = static_cast<uint32_t>(std::stoul(cat_uuid, nullptr, 16));
        static unsigned char enc_key[16];
        std::memset(enc_key, 0, sizeof(enc_key));

        std::stringstream ss_uuid;
        ss_uuid << std::hex << std::setw(8) << std::setfill('0') << uuid;
        std::string str_uuid = ss_uuid.str();

        for (size_t i = 0; i < 16; ++i) {
            enc_key[i] = (i < str_uuid.size()) ? str_uuid[i] : '0';
        }

        return enc_key;
    }
};

#endif //CAT_NET_H
