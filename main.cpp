#include <iostream>
#include <thread>
#include "cat_net.h"

int main() {
    CatNet cat_net;
    CatNet::ErrorCode err = cat_net.init("192.168.7.1", 12345, "123456");
    std::cout << "code:" << err << std::endl;
    err = cat_net.monitor(1234);
    std::cout << "code:" << err << std::endl;
    cat_net.blockedKeyboard(KEY_A, 1);
    while (1) {
        if (cat_net.isKeyboardPressed(KEY_A)) {
            std::cout << "KEY_A down" << std::endl;
            cat_net.mouseMove(-10, 10);
        }
        if (cat_net.isMousePressed(BTN_LEFT)) {
            std::cout << "BTN_LEFT down" << std::endl;
            cat_net.mouseMove(10, -10);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return 0;
}
