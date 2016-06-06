# MYSQL-client-for-STM32
MYSQL C client tested on STM32F407VG and STM32F446RE

The client is tested and working properly on STM32F4-Discovery board and Nucleo-F446RE. Also it was tested with
LwIP TCP/IP stack with external ethernet phy and with X-NUCLEO-IDW01M1 wifi module.

MAKE IT WORK:

1. You need to implement your connection function depending on what is used for internet connection. This connection function has to be implemented in mysql_write method.
2. Implement disconect function in disconnect() method.

For more info or examples contact me: ivanucherdjiev@gmail.com
