#include <iostream>
#include <thread>
#include "cat_net.h"

int main() {
     std::string cert_chain = R"()";

    std::string private_key = R"()";

    std::string ca_cert = R"()";

    CatNet cat_net;
    CatNet::ErrorCode err = cat_net.run("192.168.7.2", 12345, cert_chain, private_key, ca_cert, 5000);
    std::cout << "code:" << err << std::endl;
    if (err != CatNet::SUCCESS) {
        return 0;
    }
    err = cat_net.monitor();
    std::cout << "code:" << err << std::endl;

    for (int i = 0; i < 1000; i++) {
        cat_net.mouseMove(-1, 0);
    }

    cat_net.blockedKeyboard(KEY_A, 1);
    // cat_net.stop();
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
