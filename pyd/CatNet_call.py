import time
import signal
import sys
import catNet
import event_code #按键头文件

net = catNet.CatNet()
net.init("192.168.7.2",12345,"0fdccbf0",10)

net.monitor(1244, 10) #开启键鼠监听

net.blockedKeyboard(event_code.KEY_A, 1) #屏蔽按键A
net.blockedKeyboard(event_code.KEY_D, 1) #屏蔽按键D
net.blockedKeyboard(event_code.KEY_D, 0) #解除屏蔽按键D

net.blockedMouse(event_code.BTN_MIDDLE, 1) #屏蔽鼠标中建

net.tapKeyboardButton(event_code.KEY_F, 50) #键盘按键按下50ms后释放

net.mouseMoveAuto(-200,200,500) # x移动-200像素 y移动200像素 在500ms完成

def signal_handler(sig, frame):
    print('捕获到 Ctrl+C，正在解除所有按键屏蔽...')
    net.unblockedKeyboardAll() # 解除键盘所有屏蔽按键
    net.unblockedMouseAll() # 解除鼠标所有屏蔽按键
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


while 1:
    time.sleep(0.1)
    if net.isKeyboardPressed(event_code.KEY_A) == 1:
        print('A按下')
        net.keyboardButton(event_code.KEY_S, 1)  #模拟按键S按下
    elif net.isKeyboardPressed(event_code.KEY_A) == 0:
        net.keyboardButton(event_code.KEY_S, 0)  #模拟按键S释放

    if net.isKeyboardPressed(event_code.KEY_D) == 1:
        print('D按下') 

    if net.isMousePressed(event_code.BTN_LEFT) == 1:
        net.mouseMove(1, 2)
