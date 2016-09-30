# MYSQL-client-for-STM32
MYSQL C client tested on STM32F407VG, STM32F446RE, STM32F746 and MT7687

The client is tested and working properly on STM32F4-Discovery board and Nucleo-F446RE. Also it was tested with
LwIP TCP/IP stack with external ethernet phy and with X-NUCLEO-IDW01M1 wifi module. The MYSQL client use socket to connect to the MYSQL server and communicate with it.

MAKE IT WORK:

1. You need to implement your socket write function depending on what is used for internet connection. This socket write function has to be implemented in mysql_write method.
  - for example if you are using integrated TCP/IP stack in the STM, then you need to implement tcp_socket_write function in mysql_write method or if you are using WIFI module controlled by AT commands, then you have to implement uart_write function with proper AT command for sending data through socket.
2. Implement disconect function in disconnect() method.

For more info or examples contact me: ivanucherdjiev@gmail.com
