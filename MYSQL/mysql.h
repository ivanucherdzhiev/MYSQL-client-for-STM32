/*
 * Copyright (c) 2015, 2016
 * Ivan P. Ucherdzhiev  <ivanucherdjiev@gmail.com>
 * All Rights Reserved
 */
 
 
 
 
 /*This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.*/
	
#define mysql_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
//#include "main.h"


#define OK_PACKET     0x00
#define EOF_PACKET    0xfe
#define EOM_MES		  0xffaa
#define ERROR_PACKET  0xff
#define MAX_FIELDS    0x03//0x20   // Maximum number of fields. Reduce to save memory. Default=32
#define VERSION_STR   "1.0.4ga"
#define WITH_SELECT


#ifdef WITH_SELECT

typedef struct {
  char *name;
  char *data;
} field_struct;

typedef struct {
  int num_fields;     // actual number of fields
  char *db;
  char *table;
  field_struct *fields[MAX_FIELDS];
} column_names;

// Structure for storing row data.
typedef struct {
  char *values[MAX_FIELDS];
} row_values;

#endif


    int mysql_connect(char *user, char *password);
    void disconnect();
    int cmd_query(const char *query);
    int cmd_query_P(const char *query);
    int cmd_query_no_read(const char *query);

    int wait_for_client_limit();
    void read_packet_limit();
#ifdef WITH_SELECT
    column_names *get_columns();
    row_values *get_next_row();
    void free_columns_buffer();
    void free_row_buffer();
    void show_results();
    int clear_ok_packet();
#endif


#ifdef WITH_SELECT
    column_names columns;
    int columns_read;
    int num_cols;
#endif

    // Determine if WiFi shield is used
    #ifdef WIFI
      WiFiClient client;
    #else
     // EthernetClient client;
    #endif

    // Methods for handling packets
    int wait_for_client();
    int send_authentication_packet(char *user, char *password);
    void read_packet();
    void parse_handshake_packet();
    int check_ok_packet();
    int run_query(int query_len);
    int run_query_no_read(int query_len);

    // Utility methods
    int scramble_password(char *password, uint8_t *pwd_hash);
    int get_lcb_len(int offset);
    int read_int(int offset, int size);
    void store_int(uint8_t *buff, long value, int size);
#if defined WITH_SELECT
    char *read_string(int *offset);
    int get_field(field_struct *fs, int *off);
    int get_fields();
    int get_row_values( int *off);
    void do_query(const char *q);
#endif

