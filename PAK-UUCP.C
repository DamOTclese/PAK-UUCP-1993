
/* **********************************************************************
   * PAK-UUCP.C                                                         *
   * Gate from Packet to UUCP through FidoNet.                          *
   *                                                                    *
   * Written by Fredric L. Rice, December 1992.                         *
   * The Skeptic Tank, 1:102/890.0  (818) 335-9601.                     *
   *                                                                    *
   * Last update: 13/Aug/94                                             *
   *                                                                    *
   ********************************************************************** */

#ifdef __TURBOC__
    #include <alloc.h>
    #include <dir.h>

    #define Bios_Com            bioscom
    #define Far_Malloc          farmalloc
    #define Far_Free            farfree
    #define Find_First(a,b,c)   findfirst(a,b,c)
    #define Find_Next           findnext
    #define File_Block          ffblk
    #define Find_Name           ff_name
#else
    #include <malloc.h>

    #define Bios_Com            _bios_serialcom
    #define Far_Malloc          _fmalloc
    #define Far_Free            _ffree
    #define Find_First(a,b,c)   _dos_findfirst(a,c,b)
    #define Find_Next           _dos_findnext
    #define File_Block          find_t
    #define Find_Name           name
#endif

#include <bios.h>
#include <ctype.h>
#include <conio.h>
#include <dos.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "fossil.h"

/* **********************************************************************
   * Define various macros that will be needed.                         *
   *                                                                    *
   ********************************************************************** */

#define skipspace(s)    while (isspace(*s))  ++(s)

/* **********************************************************************
   * Define the global constants that will be used.                     *
   *                                                                    *
   ********************************************************************** */

#define TRUE                    1
#define FALSE                   0
#define BOOL                    unsigned char
#define VERSION                 "2.1"
#define ESCAPE                  27
#define INPUT_BUFFER_SIZE       200

/* **********************************************************************
   * Define macros that the System Operator may wish to change.         *
   *                                                                    *
   ********************************************************************** */

#define Connect_Time_Out  (60 * 1)      /* 1 minute connect retry       */
#define Prompt_Time_Out   (60 * 5)      /* 5 minute test for command   */

/* **********************************************************************
   * Define any prototypes which are referenced before they are seen.   *
   *                                                                    *
   ********************************************************************** */

    static void bail_out(int errorlevel);

/* **********************************************************************
   * The message file format offered here is Fido format which has      *
   * been tested with OPUS and Dutchie. It represents the latest        *
   * format that I know about.                                          *
   *                                                                    *
   ********************************************************************** */

   static struct fido_msg {
      char from[36];                  /* Who the message is from             */
      char to[36];                    /* Who the message to to               */
      char subject[72];               /* The subject of the message.         */
      char date[20];                  /* Message createion date/time         */
      unsigned int times;             /* Number of time the message was read */
      unsigned int destination_node;  /* Intended destination node           */
      unsigned int originate_node;    /* The originator node of the message  */
      unsigned int cost;              /* Cost to send this message           */
      unsigned int originate_net;     /* The originator net of the message   */
      unsigned int destination_net;   /* Intended destination net number     */
      unsigned int destination_zone;  /* Intended zone for the message       */
      unsigned int originate_zone;    /* The zone of the originating system  */
      unsigned int destination_point; /* Is there a point to destination?    */
      unsigned int originate_point;   /* The point originated the message    */
      unsigned int reply;             /* Thread to previous reply            */
      unsigned int attribute;         /* Message type                        */
      unsigned int upwards_reply;     /* Thread to next message reply        */
   } message;                         /* Something to store this structure   */

/* **********************************************************************
   * 'Attribute' bit definitions, some of which we will use             *
   *                                                                    *
   ********************************************************************** */

#define Fido_Private            0x0001
#define Fido_Crash              0x0002
#define Fido_Read               0x0004
#define Fido_Sent               0x0008
#define Fido_File_Attach        0x0010
#define Fido_Forward            0x0020
#define Fido_Orphan             0x0040
#define Fido_Kill               0x0080
#define Fido_Local              0x0100
#define Fido_Hold               0x0200
#define Fido_Reserved1          0x0400
#define Fido_File_Request       0x0800
#define Fido_Ret_Rec_Req        0x1000
#define Fido_Ret_Rec            0x2000
#define Fido_Req_Audit_Trail    0x4000
#define Fido_Update_Req         0x8000

/* **********************************************************************
   * The CONFIGURE commands are maintained in a linked list.            *
   *                                                                    *
   ********************************************************************** */

    static struct Configure {
        char *value;                    /* Pointer to the value to send */
        struct Configure *next;         /* Pointer to the next one      */
    } *c_first, *c_last, *c_point;      /* Make three pointers to it.   */

/* **********************************************************************
   * The ACCESS-BBS commands are maintained in a linked list.           *
   *                                                                    *
   ********************************************************************** */

    static struct Access_BBS {
        char *value;                    /* Pointer to the value to send */
        struct Access_BBS *next;        /* Pointer to the next one      */
    } *ab_first, *ab_last, *ab_point;   /* Make three pointers to it.   */

/* **********************************************************************
   * The READ-MAIL commands are maintained in a linked list.            *
   *                                                                    *
   ********************************************************************** */

    static struct Read_Mail {
        char *value;                    /* Pointer to the value to send */
        struct Read_Mail *next;         /* Pointer to the next one      */
    } *rm_first, *rm_last, *rm_point;   /* Make three pointers to it.   */

/* **********************************************************************
   * The DISCONNECT commands are maintained in a linked list.           *
   *                                                                    *
   ********************************************************************** */

    static struct Disconnect {
        char *value;                    /* Pointer to the value to send */
        struct Disconnect *next;        /* Pointer to the next one      */
    } *d_first, *d_last, *d_point;      /* Make three pointers to it.   */

/* **********************************************************************
   * The MATCH commands are maintained in a linked list.                *
   *                                                                    *
   ********************************************************************** */

    static struct Match {
        char *value1;                   /* Pointer to the value seen    */
        char *value2;                   /* Pointer to the response      */
        struct Match *next;             /* Pointer to the next one      */
    } *m_first, *m_last, *m_point;      /* Make three pointers to it.   */

/* **********************************************************************
   * We process the text file as lines in a linked list.                *
   *                                                                    *
   ********************************************************************** */

    static struct Text_File {
        char *value;                    /* Pointer to the value to send */
        struct Text_File *next;         /* Pointer to the next one      */
    } *tf_first, *tf_last, *tf_point;   /* Make three pointers to it.   */

/* **********************************************************************
   * We process the UUCP file as lines in a linked list.                *
   *                                                                    *
   ********************************************************************** */

    static struct UUCP_Text {
        char *value;                    /* Pointer to the value to send */
        struct UUCP_Text *next;         /* Pointer to the next one      */
    } *ut_first, *ut_last, *ut_point;   /* Make three pointers to it.   */

/* **********************************************************************
   * Message divert to holding areas due to specific keywords being     *
   * encountered is performed by maintaining a linked list of key       *
   * words.                                                             *
   *                                                                    *
   ********************************************************************** */

    static struct Divert_Key {
        char *value;                    /* Pointer to the keyword       */
        struct Divert_Key *next;        /* A pointer to the next one    */
    } *dk_first, *dk_last, *dk_point;   /* Make three pointers to it.   */

/* **********************************************************************
   * Define any local data.                                             *
   *                                                                    *
   ********************************************************************** */

    static BOOL want_diag;
    static BOOL keep_packet;
    static BOOL kill_fido;
    static BOOL want_log;
    static BOOL tnc_port_valid;
    static BOOL test_inactivity;
    static BOOL mark_immediate;
    static BOOL want_hold;
    static BOOL uucp_hold;
    static BOOL hold_b_packet;
    static BOOL last_line_blank;
    static BOOL decap_message;
    static BOOL was_period;
    static BOOL want_kludge;
    static BOOL perform_uucp;
    static time_t t_start;
    static time_t t_end;
    static char config_path[101];
    static char log_path[101];
    static char mycall[101];
    static char host[101];
    static char command_prompt[101];
    static char packet_directory[101];
    static char fidonet_directory[101];
    static char area_tag[101];
    static char divert_directory[201];
    static char packet_file_name[50];
    static char reply_path[201];
    static char uucp_address[201];
    static char packet_destination[201];
    static char input_line[INPUT_BUFFER_SIZE + 2];
    static int connect_retry;
    static int baud_rate;
    static int input_count;
    static int highest_mail;
    static unsigned int tnc_port;
    static unsigned int f_zone, f_net, f_node, f_point;
    static unsigned int g_zone, g_net, g_node, g_point;
    static FILE *file_log, *mail_file;

/* **********************************************************************
   * ErrorLevel values.                                                 *
   *                                                                    *
   ********************************************************************** */

#define No_Problem              0
#define Keyboard_Abort          1
#define Missing_Config          10
#define Configuration_Bad       11
#define Out_Of_Memory           12
#define No_FOSSIL_Driver        13
#define Bad_Com_Port_Number     14
#define TNC_Not_Powered         15
#define CD_Already_Active       16
#define Cant_Create_Mail_File   17
#define Input_Overflow          18
#define Connect_Failure         19
#define No_Command_Prompt_Seen  20
#define Cant_Open_Mail_File     21
#define Bad_System_Address      22
#define Cant_Create_MSG_File    23
#define Cant_Write_MSG_File     24
#define Config_Immediate_Error  25
#define Config_Hold_Error       26
#define Config_Kludge_Error     27
#define Connect_Failure_Abort   28
#define Lost_Connection         29
#define Process_Mail            100

/* **********************************************************************
   * Some constants.                                                    *
   *                                                                    *
   ********************************************************************** */

    static char *num_to_month[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    } ;

    static char *num_to_day[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    } ;

/* **********************************************************************
   * See if we have lost our connection.  If we have, we must perform a *
   * structured bail-out.                                               *
   *                                                                    *
   ********************************************************************** */

static void check_for_lost_connection(void)
{
    if (strstr(input_line, "*** DISCONN ") == (char *)NULL)
        return;

    bail_out(Lost_Connection);
}

/* **********************************************************************
   * We need a bit of a delay.  This is not a timed delay.              *
   *                                                                    *
   ********************************************************************** */

#ifndef __TURBOC__
static void delay(unsigned int value)
{
    for (value = value * 100; value > 0; value--);
}
#endif

/* **********************************************************************
   * day from 1-31, month from 1-12, year from 80                       *
   * Returns 0 for Sunday, etc.                                         *
   *                                                                    *
   *    This function was not written by Fredric Rice. It was taken     *
   *    from the MSGQ150S.LSH archive which is an on-line full          *
   *    screen editor.                                                  *
   *                                                                    *
   ********************************************************************** */

static int zeller(int day, int month, int year)
{
    int age;

    age = (year < 80) ? 20 : 19;

    if ((month -= 2) <= 0) {
        month += 12;
        year--;
    }

    return(((26 * month-2) / 10 +day +year +year / 4 + age / 4 - 2 * age) % 7);
}
/* **********************************************************************
   * Is the TNC powered up? Data Set Ready should be active if it is.   *
   *                                                                    *
   ********************************************************************** */

static BOOL tnc_power(unsigned com_port)
{
    return((BOOL)((Bios_Com(3, 0, com_port) & 0x20) == 0x20));
}

/* **********************************************************************
   * If there is data carrier detect, return TRUE, else, return FALSE.  *
   *                                                                    *
   ********************************************************************** */

static BOOL get_carrier_status(unsigned com_port)
{
    return((BOOL)((ComPortStat(com_port) & PS_CARRIER) > 0));
}

/* **********************************************************************
   * If there is a byte at the com port, return it, else return 0.      *
   *                                                                    *
   * If we're testing for inactivity time-out, reset the end timer.     *
   *                                                                    *
   ********************************************************************** */

static int have_byte(unsigned com_port)
{
    if (ComPortStat(com_port) & PS_RXCHARS) {
        if (test_inactivity) {
            (void)time(&t_end);
        }

        return(ComRxChar((int)com_port));
    }

    return(0);
}

/* **********************************************************************
   * Send the byte to the specified com port.                           *
   *                                                                    *
   * We reset the various timer ticks.                                  *
   *                                                                    *
   ********************************************************************** */

static char send_byte(char byte, unsigned com_port)
{
    ComTxChar(com_port, byte);
    return(byte);
}

/* **********************************************************************
   * Print the string that's offered.                                   *
   *                                                                    *
   * Append a carriage return to the end of a line feed.                *
   *                                                                    *
   ********************************************************************** */

static void print_buffer(char *this_string,
    unsigned com_port,
    BOOL echo_to_video)
{
    char byte;

    while (*this_string) {
        if (! perform_uucp) {
            byte = send_byte(*this_string++, com_port);
        }
        else {
            byte = *this_string++;
        }

        if (byte == 0x0a) {
            if (! perform_uucp) {
                (void)send_byte(0x0d, com_port);
            }
            else {
                (void)putchar(0x0d);
            }

            if (echo_to_video && !perform_uucp) {
                (void)printf("\n");
            }
        }

        if (echo_to_video) {
            (void)putchar(byte);
        }
    }
}

/* **********************************************************************
   * Initialize this project.                                           *
   *                                                                    *
   * We look for the environment variable PAKUUCP                       *
   *                                                                    *
   ********************************************************************** */

static void initialize(void)
{
    unsigned char *env;

    want_diag = FALSE;

/*
 * Get an evironment variable if tere is one and make paths to
 * both the configuration file and the logging file.
 */

    if ((char *)NULL == (env = getenv("PAKUUCP"))) {
        (void)strcpy(config_path, "PAK-UUCP.CFG");
        (void)strcpy(log_path, "PAK-UUCP.LOG");
    }
    else {
        (void)strcpy(config_path, env);
        (void)strcpy(log_path, env);

        if (config_path[strlen(config_path) - 1] != '\\') {
            (void)strcat(config_path, "\\");
            (void)strcat(log_path, "\\");
        }

        (void)strcat(config_path, "PAK-UUCP.CFG");
        (void)strcat(log_path, "PAK-UUCP.LOG");
    }

/*
 * Initialize everything
 */

    want_log =          FALSE;
    keep_packet =       FALSE;
    kill_fido =         TRUE;
    tnc_port_valid =    FALSE;
    test_inactivity =   FALSE;
    mark_immediate =    FALSE;
    want_hold =         FALSE;
    uucp_hold =         TRUE;
    hold_b_packet =     TRUE;
    last_line_blank =   FALSE;
    decap_message =     FALSE;
    was_period =        FALSE;
    want_kludge =       TRUE;
    perform_uucp =      FALSE;

    mycall[0] =            (char)NULL;
    host[0] =              (char)NULL;
    command_prompt[0] =    (char)NULL;
    packet_directory[0] =  (char)NULL;
    fidonet_directory[0] = (char)NULL;
    area_tag[0] =          (char)NULL;
    reply_path[0] =        (char)NULL;
    divert_directory[0] =  (char)NULL;

    connect_retry = 5;
    tnc_port =      0;
    baud_rate =     1200;
    highest_mail =  0;

    c_first = c_last = c_point =    (struct Configure *)NULL;
    ab_first = ab_last = ab_point = (struct Access_BBS *)NULL;
    rm_first = rm_last = rm_point = (struct Read_Mail *)NULL;
    d_first = d_last = d_point =    (struct Disconnect *)NULL;
    m_first = m_last = m_point =    (struct Match *)NULL;
    tf_first = tf_last = tf_point = (struct Text_File *)NULL;
    ut_first = ut_last = ut_point = (struct UUCP_Text *)NULL;
    dk_first = dk_last = dk_point = (struct Divert_Key *)NULL;

    mail_file = (FILE *)NULL;
    file_log =  (FILE *)NULL;
}

/* **********************************************************************
   * MYCALL {call-sign}                                                 *
   *                                                                    *
   ********************************************************************** */

static void plug_mycall(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;
    (void)strcpy(mycall, atpoint);

    if (want_diag)
        (void)printf("DIAG: mycall {%s}\n", mycall);
}

/* **********************************************************************
   * HOST {call-sign}                                                   *
   *                                                                    *
   ********************************************************************** */

static void plug_host(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;
    (void)strcpy(host, atpoint);

    if (want_diag)
        (void)printf("DIAG: host {%s}\n", host);
}

/* **********************************************************************
   * CONNECT-RETRY {value}                                              *
   *                                                                    *
   ********************************************************************** */

static void plug_connect_retry(char *atpoint)
{
    connect_retry = atoi(atpoint);

    if (connect_retry < 1 || connect_retry > 20) {
        (void)printf("CONFIG: connect-retry value out of range: 1 to 20\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    if (want_diag)
        (void)printf("DIAG: connect-retry {%d}\n", connect_retry);
}

/* **********************************************************************
   * CONFIGURE {string 1}                                               *
   * CONFIGURE {string 2}                                               *
   * CONFIGURE {string n}                                               *
   *                                                                    *
   ********************************************************************** */

static void plug_configure(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;

/*
 * Allocate memory for the structure
 */

    c_point = (struct Configure *)Far_Malloc(sizeof(struct Configure));

    if (c_point == (struct Configure *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }

/*
 * Allocate memory for the date
 */

    c_point->value = (char *)Far_Malloc(strlen(atpoint) + 1);

    if (c_point->value == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(c_point->value, atpoint);

/*
 * Append the entry in the linked list.
 */

    c_point->next = (struct Configure *)NULL;

    if (c_first == (struct Configure *)NULL) {
        c_first = c_point;
    }
    else {
        c_last->next = c_point;
    }

    c_last = c_point;

    if (want_diag)
        (void)printf("DIAG: configure {%s}\n", c_point->value);
}

/* **********************************************************************
   * ACCESS-BBS {string 1}                                              *
   * ACCESS-BBS {string 2}                                              *
   * ACCESS-BBS {string n}                                              *
   *                                                                    *
   ********************************************************************** */

static void plug_access_bbs(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;

    if (*atpoint != '"' || atpoint[strlen(atpoint) - 1] != '"') {
        (void)printf("CONFIG: access-bbs string not in quotations\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    atpoint++;

/*
 * Allocate memory for the structure
 */

    ab_point = (struct Access_BBS *)Far_Malloc(sizeof(struct Access_BBS));

    if (ab_point == (struct Access_BBS *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }

/*
 * Allocate memory for the data
 */

    ab_point->value = (char *)Far_Malloc(strlen(atpoint) + 1);

    if (ab_point->value == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(ab_point->value, atpoint);
    ab_point->value[strlen(ab_point->value) - 1] = (char)NULL;

/*
 * Append the entry in the linked list.
 */

    ab_point->next = (struct Access_BBS *)NULL;

    if (ab_first == (struct Access_BBS *)NULL) {
        ab_first = ab_point;
    }
    else {
        ab_last->next = ab_point;
    }

    ab_last = ab_point;

    if (want_diag)
        (void)printf("DIAG: access-bbs {%s}\n", ab_point->value);
}

/* **********************************************************************
   * COMMAND-PROMPT "string"                                            *
   *                                                                    *
   ********************************************************************** */

static void plug_command_prompt(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;

    if (*atpoint != '"' || atpoint[strlen(atpoint) - 1] != '"') {
        (void)printf("CONFIG: command-prompt string not in quotations\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    atpoint++;

    (void)strcpy(command_prompt, atpoint);
    command_prompt[strlen(command_prompt) - 1] = (char)NULL;

    if (want_diag)
        (void)printf("DIAG: command-prompt {%s}\n", command_prompt);
}

/* **********************************************************************
   * READ-MAIL {string 1}                                               *
   * READ-MAIL {string 2}                                               *
   * READ-MAIL {string n}                                               *
   *                                                                    *
   ********************************************************************** */

static void plug_read_mail(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;

    if (*atpoint != '"' || atpoint[strlen(atpoint) - 1] != '"') {
        (void)printf("CONFIG: read-mail string not in quotations\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    atpoint++;

/*
 * Allocate memory for the structure
 */

    rm_point = (struct Read_Mail *)Far_Malloc(sizeof(struct Read_Mail));

    if (rm_point == (struct Read_Mail *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }

/*
 * Allocate memory for the data
 */

    rm_point->value = (char *)Far_Malloc(strlen(atpoint) + 1);

    if (rm_point->value == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(rm_point->value, atpoint);
    rm_point->value[strlen(rm_point->value) - 1] = (char)NULL;

/*
 * Append the entry in the linked list.
 */

    rm_point->next = (struct Read_Mail *)NULL;

    if (rm_first == (struct Read_Mail *)NULL) {
        rm_first = rm_point;
    }
    else {
        rm_last->next = rm_point;
    }

    rm_last = rm_point;

    if (want_diag)
        (void)printf("DIAG: read-mail {%s}\n", rm_point->value);
}

/* **********************************************************************
   * DISCONNECT {string 1}                                              *
   * DISCONNECT {string 2}                                              *
   * DISCONNECT {string n}                                              *
   *                                                                    *
   ********************************************************************** */

static void plug_disconect(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;

    if (*atpoint != '"' || atpoint[strlen(atpoint) - 1] != '"') {
        (void)printf("CONFIG: disconnect string not in quotations\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    atpoint++;

/*
 * Allocate memory for the structure
 */

    d_point = (struct Disconnect *)Far_Malloc(sizeof(struct Disconnect));

    if (d_point == (struct Disconnect *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }

/*
 * Allocate memory for the data
 */

    d_point->value = (char *)Far_Malloc(strlen(atpoint) + 1);

    if (d_point->value == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(d_point->value, atpoint);
    d_point->value[strlen(d_point->value) - 1] = (char)NULL;

/*
 * Append the entry in the linked list.
 */

    d_point->next = (struct Disconnect *)NULL;

    if (d_first == (struct Disconnect *)NULL) {
        d_first = d_point;
    }
    else {
        d_last->next = d_point;
    }

    d_last = d_point;

    if (want_diag)
        (void)printf("DIAG: disconnect {%s}\n", d_point->value);
}

/* **********************************************************************
   * MATCH "string 1a" with "string 1b"                                 *
   * MATCH "string 2a" with "string 2b"                                 *
   * MATCH "string na" with "string nb"                                 *
   *                                                                    *
   ********************************************************************** */

static void plug_match(char *atpoint)
{
    int count;
    char test_string1[51], test_string2[51];

/*
 * Allocate memory for the structure
 */

    m_point = (struct Match *)Far_Malloc(sizeof(struct Match));

    if (m_point == (struct Match *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }

/*
 * Get the first string contained within quotation marks
 */

    count = 0;
    while (*atpoint && *atpoint != '"') atpoint++;

    if (*atpoint != '"') {
        (void)printf("CONFIG: 1 match syntax incorrect\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    atpoint++;

    while (*atpoint && *atpoint != '"')
        test_string1[count++] = *atpoint++;

    test_string1[count] = (char)NULL;

    if (*atpoint != '"') {
        (void)printf("CONFIG: 2 match syntax incorrect\n");
        fcloseall();
        exit(Configuration_Bad);
    }

/*
 * See if there is a "with" in the syntax
 */

    atpoint++;
    skipspace(atpoint);

    if (strnicmp(atpoint, "with", 4)) {
        (void)printf("CONFIG: 3 match syntax incorrect\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    atpoint += 4;
    skipspace(atpoint);

/*
 * Get the second string from the line.
 */

    count = 0;
    while (*atpoint && *atpoint != '"') atpoint++;

    if (*atpoint != '"') {
        (void)printf("CONFIG: 5 match syntax incorrect\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    atpoint++;

    while (*atpoint && *atpoint != '"')
        test_string2[count++] = *atpoint++;

    test_string2[count] = (char)NULL;

    if (*atpoint != '"') {
        (void)printf("CONFIG: 6 match syntax incorrect\n");
        fcloseall();
        exit(Configuration_Bad);
    }

/*
 * Store the strings.
 */

    m_point->value1 = (char *)Far_Malloc(strlen(test_string1) + 1);

    if (m_point->value1 == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(m_point->value1, test_string1);

    m_point->value2 = (char *)Far_Malloc(strlen(test_string2) + 1);

    if (m_point->value2 == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(m_point->value2, test_string2);

/*
 * Append the entry in the linked list.
 */

    m_point->next = (struct Match *)NULL;

    if (m_first == (struct Match *)NULL) {
        m_first = m_point;
    }
    else {
        m_last->next = m_point;
    }

    m_last = m_point;

    if (want_diag)
        (void)printf("DIAG: match {%s} with {%s}\n",
            m_point->value1, m_point->value2);
}

/* **********************************************************************
   * KEEP-PACKET {YES || NO}                                            *
   *                                                                    *
   ********************************************************************** */

static void plug_keep_packet(char *atpoint)
{
    if (! strnicmp(atpoint, "YES", 3)) {
        keep_packet = TRUE;
    }
    else if (! strnicmp(atpoint, "NO", 2)) {
        keep_packet = FALSE;
    }
    else {
        (void)printf("CONFIG: keep-packet value should be YES or NO\n");
        fcloseall();
        exit(Configuration_Bad);
    }

    if (want_diag)
        (void)printf("DIAG: keep-packet {%s}\n", keep_packet ? "yes" : "no");
}

/* **********************************************************************
   * KILL-FIDO {YES || NO}                                              *
   *                                                                    *
   ********************************************************************** */

static void plug_kill_fido(char *atpoint)
{
    if (! strnicmp(atpoint, "YES", 3)) {
        kill_fido = TRUE;
    }
    else if (! strnicmp(atpoint, "NO", 2)) {
        kill_fido = FALSE;
    }
    else {
        (void)printf("CONFIG: kill-fido value should be YES or NO\n");
        fcloseall();
        exit(Configuration_Bad);
    }                                  

    if (want_diag)
        (void)printf("DIAG: kill-fido {%s}\n", kill_fido ? "yes" : "no");
}

/* **********************************************************************
   * PACKET-DIRECTORY {string}                                          *
   *                                                                    *
   ********************************************************************** */

static void plug_packet_directory(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;
    (void)strcpy(packet_directory, atpoint);

    if (want_diag)
        (void)printf("DIAG: packet-directory {%s}\n", packet_directory);
}

/* **********************************************************************
   * FIDONET-DIRECTORY {string}                                         *
   *                                                                    *
   ********************************************************************** */

static void plug_fidonet_directory(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;
    (void)strcpy(fidonet_directory, atpoint);

    if (want_diag)
        (void)printf("DIAG: fidonet-directory {%s}\n", fidonet_directory);
}

/* **********************************************************************
   * AREA {string}                                                      *
   *                                                                    *
   ********************************************************************** */

static void plug_area(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;
    (void)strcpy(area_tag, atpoint);

    if (want_diag)
        (void)printf("DIAG: area_tag {%s}\n", area_tag);
}

/* **********************************************************************
   * LOG {YES || NO}                                                    *
   *                                                                    *
   ********************************************************************** */

static void plug_log(char *atpoint)
{
    if (! strnicmp(atpoint, "YES", 3)) {
        want_log = TRUE;
    }
    else if (! strnicmp(atpoint, "NO", 2)) {
        want_log = FALSE;
    }
    else {
        (void)printf("CONFIG: want_log value should be YES or NO\n");
        fcloseall();
        exit(Configuration_Bad);
    }                                  

    if (want_diag)
        (void)printf("DIAG: log {%s}\n", want_log ? "yes" : "no");
}

/* **********************************************************************
   * TNC-BAUD {19200 || 9600 || 4800 || 2400 || 1200}                   *
   *                                                                    *
   ********************************************************************** */

static void plug_baud(char *atpoint)
{
    int rate;

    rate = atoi(atpoint);

    switch(rate) {
        case 19200:
            baud_rate = CP_B19200;
            break;

        case 9600:
            baud_rate = CP_B9600;
            break;

        case 4800:
            baud_rate = CP_B4800;
            break;

        case 2400:
            baud_rate = CP_B2400;
            break;

        case 1200:
            baud_rate = CP_B1200;
            break;

        default:
            (void)printf("CONFIG: tnc-baud value is invalid: %d\n", rate);
            fcloseall();
            exit(Configuration_Bad);
    }

    if (want_diag)
        (void)printf("DIAG: tnc-baud {%d}\n", rate);
}

/* **********************************************************************
   * We have an IMMEDIATE command.                                      *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_immediate(char *atpoint)
{
    if (! strnicmp(atpoint, "yes", 3)) {
        mark_immediate = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        mark_immediate = FALSE;
    }
    else {
        (void)printf("Config file error: IMMEDIATE command parameter!\n");
        fcloseall();
        exit(Config_Immediate_Error);
    } 

    if (want_diag)
        (void)printf("DIAG: immediate with {%s}\n", mark_immediate ? "yes" : "no");
}

/* **********************************************************************
   * We have a HOLD command.                                            *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_hold(char *atpoint)
{
    if (! strnicmp(atpoint, "yes", 3)) {
        want_hold = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        want_hold = FALSE;
    }
    else {
        (void)printf("Config file error: HOLD command parameter!\n");
        fcloseall();
        exit(Config_Hold_Error);
    }

    if (want_diag)
        (void)printf("DIAG: hold with {%s}\n", want_hold ? "yes" : "no");
}

/* **********************************************************************
   * We have a PHOLD command.                                           *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_hold_packet(char *atpoint)
{
    if (! strnicmp(atpoint, "yes", 3)) {
        hold_b_packet = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        hold_b_packet = FALSE;
    }
    else {
        (void)printf("Config file error: PHOLD command parameter!\n");
        fcloseall();
        exit(Config_Hold_Error);
    }

    if (want_diag)
        (void)printf("DIAG: phold with {%s}\n", hold_b_packet ? "yes" : "no");
}

/* **********************************************************************
   * We have a UHOLD command.                                           *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_hold_uucp(char *atpoint)
{
    if (! strnicmp(atpoint, "yes", 3)) {
        uucp_hold = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        uucp_hold = FALSE;
    }
    else {
        (void)printf("Config file error: UHOLD command parameter!\n");
        fcloseall();
        exit(Config_Hold_Error);
    }

    if (want_diag)
        (void)printf("DIAG: uhold with {%s}\n", uucp_hold ? "yes" : "no");
}

/* **********************************************************************
   * Extract the network address from the string offered and stuff      *
   * everything into the addresses memory bytes offered.                *
   *                                                                    *
   ********************************************************************** */

static void plug_address(char *atpoint,
    unsigned int *zone,
    unsigned int *net,
    unsigned int *node,
    unsigned int *point)
{
/*
 * Extract systems zone
 */

    *zone = atoi(atpoint);

/*
 * Toss digits which comprise the zone
 */

    while (*atpoint >= '0' && *atpoint <= '9') atpoint++;

/*
 * Make sure the next character is a :. If it's not (like an end of
 * string or a carriage return) thenwe've not got a full address.
 */

    if (*atpoint != ':' || *zone < 1) {
        (void)printf("SYSTEM command has unusual network address!\n");
        fcloseall();
        exit(Bad_System_Address);
    }

/*
 * Skip past the :
 */

    atpoint++;

/*
 * Extract the network
 */

    *net = atoi(atpoint);

/*
 * Skip past the network digits
 */

    while (*atpoint >= '0' && *atpoint <= '9') atpoint++;

/*
 * See if the next character is a /
 */

    if (*atpoint != '/' || *net < 1) {
        (void)printf("SYSTEM command has unusual network address!\n");
        fcloseall();
        exit(Bad_System_Address);
    }

/*
 * Skip past the /
 */

    atpoint++;

/*
 * Extract the node number
 */

    *node = atoi(atpoint);

/*
 * Skip past the node number
 */

    while (*atpoint >= '0' && *atpoint <= '9') atpoint++;

/*
 * If the next character is not a . then the address is strange.
 */

    if (*atpoint != '.' || *node == 0) {
        (void)printf("SYSTEM command has unusual network address!\n");
        fcloseall();
        exit(Bad_System_Address);
    }

/*
 * Skip past the .
 */

    atpoint++;

/*
 * Extract the point number.
 */

    *point = atoi(atpoint);

    if (want_diag) {
        (void)printf("DIAG: Network address {%d:%d/%d.%d}\n",
            *zone, *net, *node, *point);
    }
}

/* **********************************************************************
   * We have a KLUDGE command.                                          *
   *                                                                    *
   * The only permitted values are YES || NO.                           *
   *                                                                    *
   ********************************************************************** */

static void plug_kludge(char *atpoint)
{
    if (! strnicmp(atpoint, "yes", 3)) {
        want_kludge = TRUE;
    }
    else if (! strnicmp(atpoint, "no", 2)) {
        want_kludge = FALSE;
    }
    else {
        (void)printf("Config file error: KLUDGE command parameter!\n");
        fcloseall();
        exit(Config_Kludge_Error);
    } 

    if (want_diag)
        (void)printf("DIAG: kludge with {%s}\n", want_kludge ? "yes" : "no");
}

/* **********************************************************************
   * We have a DIVERT-DIRECTORY command.                                *
   *                                                                    *
   * The permitted response is a subdirectory path name.                *
   *                                                                    *
   ********************************************************************** */

static void plug_divert(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;

    (void)strcpy(divert_directory, atpoint);

    if (divert_directory[strlen(divert_directory) - 1] != '\\')
        (void)strcat(divert_directory, "\\");

    if (want_diag)
        (void)printf("DIAG: divert-directory with {%s}\n", divert_directory);
}

/* **********************************************************************
   * We have a FLAG command.                                            *
   *                                                                    *
   ********************************************************************** */

static void plug_flag(char *atpoint)
{
    atpoint[strlen(atpoint) - 1] = (char)NULL;

    dk_point = (struct Divert_Key *)Far_Malloc(sizeof(struct Divert_Key));

    if (dk_point == (struct Divert_Key *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }

/*
 * Allocate memory for the value
 */

    dk_point->value = (char *)Far_Malloc(strlen(atpoint) + 1);

    if (dk_point->value == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(dk_point->value, atpoint);

/*
 * Append the entry in the linked list.
 */

    dk_point->next = (struct Divert_Key *)NULL;

    if (dk_first == (struct Divert_Key *)NULL) {
        dk_first = dk_point;
    }
    else {
        dk_last->next = dk_point;
    }

    dk_last = dk_point;

    if (want_diag)
        (void)printf("DIAG: flag {%s}\n", dk_point->value);
}

/* **********************************************************************
   * Extract configuration information.                                 *
   *                                                                    *
   ********************************************************************** */

static void extract_configuration(void)
{
    unsigned char record[201], *atpoint;
    FILE *config;

/*
 * Open up the configuration file.
 */

    if ((config = fopen(config_path, "rt")) == (FILE *)NULL) {
        (void)printf("I was unable to find config file: %s\n", config_path);
        fcloseall();
        exit(Missing_Config);
    }

/*
 * Extract each line and parse it out, calling the function which
 * will do the majority of the work.
 */

    while (! feof(config)) {
        (void)fgets(record, 200, config);

        if (! feof(config)) {
            atpoint = record;
            skipspace(atpoint);

            if (! strnicmp(atpoint, "mycall", 6)) {
                atpoint += 6;
                skipspace(atpoint);
                plug_mycall(atpoint);
            }
            else if (! strnicmp(atpoint, "host", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_host(atpoint);
            }
            else if (! strnicmp(atpoint, "connect-retry", 13)) {
                atpoint += 13;
                skipspace(atpoint);
                plug_connect_retry(atpoint);
            }
            else if (! strnicmp(atpoint, "configure", 9)) {
                atpoint += 9;
                skipspace(atpoint);
                plug_configure(atpoint);
            }
            else if (! strnicmp(atpoint, "access-bbs", 10)) {
                atpoint += 10;
                skipspace(atpoint);
                plug_access_bbs(atpoint);
            }
            else if (! strnicmp(atpoint, "command-prompt", 14)) {
                atpoint += 14;
                skipspace(atpoint);
                plug_command_prompt(atpoint);
            }
            else if (! strnicmp(atpoint, "read-mail", 9)) {
                atpoint += 9;
                skipspace(atpoint);
                plug_read_mail(atpoint);
            }
            else if (! strnicmp(atpoint, "disconnect", 10)) {
                atpoint += 10;
                skipspace(atpoint);
                plug_disconect(atpoint);
            }
            else if (! strnicmp(atpoint, "match", 5)) {
                atpoint += 5;
                skipspace(atpoint);
                plug_match(atpoint);
            }
            else if (! strnicmp(atpoint, "keep-packet", 11)) {
                atpoint += 11;
                skipspace(atpoint);
                plug_keep_packet(atpoint);
            }
            else if (! strnicmp(atpoint, "kill-fido", 9)) {
                atpoint += 9;
                skipspace(atpoint);
                plug_kill_fido(atpoint);
            }
            else if (! strnicmp(atpoint, "packet-directory", 16)) {
                atpoint += 16;
                skipspace(atpoint);
                plug_packet_directory(atpoint);
            }
            else if (! strnicmp(atpoint, "fidonet-directory", 17)) {
                atpoint += 17;
                skipspace(atpoint);
                plug_fidonet_directory(atpoint);
            }
            else if (! strnicmp(atpoint, "area", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_area(atpoint);
            }
            else if (! strnicmp(atpoint, "log", 3)) {
                atpoint += 3;
                skipspace(atpoint);
                plug_log(atpoint);
            }
            else if (! strnicmp(atpoint, "tnc-baud", 8)) {
                atpoint += 8;
                skipspace(atpoint);
                plug_baud(atpoint);
            }
            else if (! strnicmp(atpoint, "system", 6)) {
                atpoint += 6;
                skipspace(atpoint);
                plug_address(atpoint, &f_zone, &f_net, &f_node, &f_point);
            }
            else if (! strnicmp(atpoint, "gate", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_address(atpoint, &g_zone, &g_net, &g_node, &g_point);
            }
            else if (! strnicmp(atpoint, "immediate", 9)) {
                atpoint += 9;
                skipspace(atpoint);
                plug_immediate(atpoint);
            }
            else if (! strnicmp(atpoint, "hold", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_hold(atpoint);
            }
            else if (! strnicmp(atpoint, "phold", 5)) {
                atpoint += 5;
                skipspace(atpoint);
                plug_hold_packet(atpoint);
            }
            else if (! strnicmp(atpoint, "uhold", 5)) {
                atpoint += 5;
                skipspace(atpoint);
                plug_hold_uucp(atpoint);
            }
            else if (! strnicmp(atpoint, "kludge", 6)) {
                atpoint += 6;
                skipspace(atpoint);
                plug_kludge(atpoint);
            }
            else if (! strnicmp(atpoint, "divert-directory", 16)) {
                atpoint += 16;
                skipspace(atpoint);
                plug_divert(atpoint);
            }
            else if (! strnicmp(atpoint, "flag", 4)) {
                atpoint += 4;
                skipspace(atpoint);
                plug_flag(atpoint);
            }
        }
    }

    (void)fclose(config);
}

/* **********************************************************************
   * Open-up the communications port.                                   *
   *                                                                    *
   * We use a FOSSIL driver.  Both X00.SYS or BNU.SYS have been tested. *
   *                                                                    *
   ********************************************************************** */

static void open_up_communications_port(void)
{
    struct finfo fossil_information;

    if (ComPortInit(tnc_port, 0, &fossil_information) != FSIG) {
        (void)printf("No FOSSIL driver was found!\n");
        delay(300);
        exit(No_FOSSIL_Driver);
    }

/*
    Program TNC 8 data, 1 stop, no parity, 9600 baud.
    Set CTS and DTE
*/

    ComPortSet(tnc_port, baud_rate | CP_8N1);
    ComFlowCtl(tnc_port, FC_LOCCTS);
}

/* **********************************************************************
   * Check power and carrier detect before we do anything else.         *
   *                                                                    *
   ********************************************************************** */

static void check_the_tnc(void)
{
    if (! tnc_power(tnc_port)) {
        (void)printf("TNC does not have power! %x\n",
            Bios_Com(3, 0, tnc_port));

        bail_out(TNC_Not_Powered);
    }

    if (get_carrier_status(tnc_port)) {
        (void)printf("Carrier already present on TNC! %x\n",
            Bios_Com(3, 0, tnc_port));

        bail_out(CD_Already_Active);
    }
}

/* **********************************************************************
   * Create a new mail file.                                            *
   *                                                                    *
   * The file name is composed of:                                      *
   *    MONTH DAY HOUR MINUTE .MIN                                      *
   *                                                                    *
   ********************************************************************** */

static void open_up_mail_file(void)
{
    time_t the_time;
    struct tm *local_time;

    (void)time(&the_time);
    local_time = localtime(&the_time);

/*
 * Build file name so that it is unique.  We don't want to loose our
 * files until a whole year has gone by.
 */

    (void)sprintf(packet_file_name, "%s%02d%02d%02d%02d.MIN",
        packet_directory,
        local_time->tm_mon + 1,
        local_time->tm_mday,
        local_time->tm_hour,
        local_time->tm_min);

    if ((mail_file = fopen(packet_file_name, "wb")) == (FILE *)NULL) {
        (void)printf("Cant create mail file: %s!\n", packet_file_name);
        fcloseall();
        exit(Cant_Create_Mail_File);
    }                             
}

/* **********************************************************************
   * Take what's at the TNC port and store to the mail file.            *
   *                                                                    *
   * Make sure that we don't overflow the input buffer.                 *
   *                                                                    *
   ********************************************************************** */

static void scan_input_buffer(void)
{
    int byte;

    byte = 1;

    while (byte != 0) {
        byte = have_byte(tnc_port);

        if (byte != 0) {
            if (byte != 0x0a) {
                (void)fputc(byte, mail_file);

                if (byte == 0x0d) {
                    (void)fputc(0x0a, mail_file);
                }
            }

            if (want_diag)
                (void)putchar(byte);

            if (byte == 0x0d) {
                input_count = 0;
            }
            else {
                if (input_count == INPUT_BUFFER_SIZE) {
                    (void)printf("Input overflow!\n");
                    fcloseall();
                    exit(Input_Overflow);
                }

                input_line[input_count++] = (char)byte;
                input_line[input_count] = (char)NULL;
            }
        }
    }
}

/* **********************************************************************
   * Send a disconnect to the TNC and bail out.                         *
   *                                                                    *
   ********************************************************************** */

static void bail_out(int errorlevel)
{
    (void)send_byte(0x03, tnc_port);
    delay(100);
    (void)send_byte('d', tnc_port);
    (void)send_byte(0x0d, tnc_port);
    delay(300);
    scan_input_buffer();

    ComPortDeInit(tnc_port);

    if (errorlevel != Process_Mail) {
        fcloseall();
        exit(errorlevel);
    }
}

/* **********************************************************************
   * Send mycall and then configures.                                   *
   *                                                                    *
   * These are sent first so that the TNC is configured.  There is no   *
   * connection present when this is performed.                         *
   *                                                                    *
   ********************************************************************** */

static void send_configuration(void)
{
    char record[101];

    (void)printf("Sending configuration to TNC...\n");

/*
 * Get some attention
 */

    (void)send_byte(0x03, tnc_port);
    delay(50);

/*
 * Get command prompt
 */

    (void)send_byte(0x0d, tnc_port);
    delay(50);

/*
 * Scan the buffer and throw it away
 */

    scan_input_buffer();

/*
 * Send packet call sign so that packet host will answer
 */

    (void)sprintf(record, "mycall %s%c", mycall, 0x0d);
    print_buffer(record, tnc_port, want_diag);
    delay(50);
    scan_input_buffer();

/*
 * Go through the linked list and send all lines.
 */

    c_point = c_first;

    while (c_point) {
        (void)sprintf(record, "%s%c", c_point->value, 0x0d);
        print_buffer(record, tnc_port, want_diag);
        delay(40);
        scan_input_buffer();
        c_point = c_point->next;
    }
}

/* **********************************************************************
   * Send all of the access-bbs strings to the TNC.                     *
   *                                                                    *
   * These are sent after a connection is made.  On some packet hosts   *
   * the Packet system will drop down to a C:> command prompt.  These   *
   * (if there are any) are sent to access the BBS from whatever mode   *
   * the Packet Host adopts after a connect.  These are designed to     *
   * access the BBS menu.                                               *
   *                                                                    *
   ********************************************************************** */

static void send_bbs_access_strings(void)
{
    char record[101];

    delay(100);
    scan_input_buffer();
    check_for_lost_connection();

    (void)printf("Sending access-bbs strings...\n");

/*
 * Go through the linked list and send them one at a time.
 */

    ab_point = ab_first;

    while (ab_point) {
        (void)sprintf(record, "%s%c", ab_point->value, 0x0d);
        print_buffer(record, tnc_port, want_diag);
        delay(100);
        scan_input_buffer();
        check_for_lost_connection();
        ab_point = ab_point->next;
    }                
}

/* **********************************************************************
   * Send the read-mail strings.                                        *
   *                                                                    *
   * Now that we have a BBS command prompt, send the strings which will *
   * cause the Packet Host to read all of the mail that we are          *
   * interested in.                                                     *
   *                                                                    *
   ********************************************************************** */

static void send_read_mail_strings(void)
{
    char record[101];

    (void)printf("Sending read-mail strings...\n");

/*
 * Go through the linked list and send each line.
 */

    rm_point = rm_first;

    while (rm_point) {
        (void)sprintf(record, "%s%c", rm_point->value, 0x0d);
        print_buffer(record, tnc_port, want_diag);
        delay(100);
        scan_input_buffer();
        check_for_lost_connection();
        rm_point = rm_point->next;
    }                
}

/* **********************************************************************
   * Mark the end of the inbound mail reads.                            *
   *                                                                    *
   ********************************************************************** */

static void mark_end_of_inbound(void)
{
    char record[101];

/*
 * Mark the MIN file to indicate that what follows should be the
 * end of the text to scan. This is done so that we don't start
 * looking for messages in the download file after this point on.
 */

    (void)sprintf(record, "%c%c-|end|-%c%c", 0x0d, 0x0a, 0x0d, 0x0a);
    (void)fputs(record, mail_file);
}

/* **********************************************************************
   * Send the disconnect strings.                                       *
   *                                                                    *
   * We are through with the Packet Host and wish to disconnect.  We    *
   * may need to go through various layers of menus to do so yet        *
   * usually one single command does it for most host systems.          *
   *                                                                    *
   ********************************************************************** */

static void send_disconnect_strings(void)
{
    char record[101];

    (void)printf("Sending disconnect strings...\n");

/*
 * Send each command one at a time
 */

    d_point = d_first;

    while (d_point) {
        (void)sprintf(record, "%s%c", d_point->value, 0x0d);
        print_buffer(record, tnc_port, want_diag);
        delay(100);
        scan_input_buffer();
        d_point = d_point->next;
    }

    delay(500);
}

/* **********************************************************************
   * Tell everyone we're ready and willing to run.                      *
   *                                                                    *
   ********************************************************************** */

static void say_hello(void)
{
    (void)printf("\nPAK-UUCP version " VERSION "\n\n");
}

/* **********************************************************************
   * See if we got a connected to string.                               *
   *                                                                    *
   ********************************************************************** */

static BOOL found_connect(void)
{
    return((BOOL)(strstr(input_line, "*** CONNECTED to ") != (char *)NULL));
}

/* **********************************************************************
   * We check for the command_prompt string in the input line and if    *
   * it is found, we return, else we check to see if we have a match    *
   * prompt. If a match prompt is located, we offer the response string *
   * and then continue to wait.                                         *
   *                                                                    *
   * When the command-prompt is found, we return TRUE.                  *
   *                                                                    *
   * We will wait for the specified time-out and then we'll return      *
   * with a FALSE to indicate that we were never prompted.              *
   *                                                                    *
   ********************************************************************** */

static BOOL wait_for_command_prompt(BOOL inactivity_timeout)
{
    char record[201];
    unsigned char THERE_IS_LIFE = TRUE;

    test_inactivity = inactivity_timeout;

    (void)time(&t_start);
    (void)time(&t_end);

    (void)printf("Waiting for BBS command prompt... Hit [ESC] to abort.\n");

    while(THERE_IS_LIFE) {
        scan_input_buffer();
        check_for_lost_connection();

        if (strstr(input_line, command_prompt) != (char *)NULL) {
            return(TRUE);
        }

        m_point = m_first;

        while (m_point) {
            if (strstr(input_line, m_point->value1) != (char *)NULL) {
                (void)sprintf(record, "%s%c", m_point->value2, 0x0d);
                print_buffer(record, tnc_port, want_diag);
                input_line[0] = (char)NULL;
                input_count = 0;
            }

            m_point = m_point->next;
        }

        if (difftime(t_end, t_start) > Prompt_Time_Out) {
            return(FALSE);
        }

        if (kbhit() != 0) {
            if (getch() == 27) {
                THERE_IS_LIFE = FALSE;
                bail_out(Keyboard_Abort);
            }
        }

        (void)time(&t_end);
    }
}

/* **********************************************************************
   * Make a connection attempt and then wait one minute for a connect.  *
   *                                                                    *
   ********************************************************************** */

static BOOL make_connect_attempt(char *aborted)
{
    char record[201];
    unsigned char THERE_IS_LIFE = TRUE;

    (void)printf("Sending connect request to: %s. Hit [ESC] to abort\n", host);

/*
 * Get the current time
 */

    (void)time(&t_start);
    (void)time(&t_end);

    (void)sprintf(record, "c %s%c", host, 0x0d);
    print_buffer(record, tnc_port, want_diag);

    *aborted = FALSE;

/*
 * Go into a forever loop, scanning the input from the TNC
 * and then checking it for a connect message.  Also check to
 * see if the time duration is exceeded.
 *
 * Finally, check the local keyboard for an ESCAPE so that
 * the operator may bail-out of the connect gracefully.
 */

    while(THERE_IS_LIFE) {
        scan_input_buffer();

        if (found_connect()) {
            return(TRUE);
        }

        if (difftime(t_end, t_start) > Connect_Time_Out) {
            return(FALSE);
        }

        (void)time(&t_end);

        if (kbhit() != 0) {
            if (getch() == ESCAPE) {
                *aborted = TRUE;
                return(FALSE);
            }
        }
    }
}

/* **********************************************************************
   * Append the linked list with the message text.                      *
   *                                                                    *
   ********************************************************************** */

static void plug_message_text(char *atpoint)
{
    char *testing;
    char new_address[401];
    struct Text_File *tf_hold;

    atpoint[strlen(atpoint) - 1] = (char)NULL;

/*
 * Allocate memory for the structure
 */

    tf_point = (struct Text_File *)Far_Malloc(sizeof(struct Text_File));

    if (tf_point == (struct Text_File *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }

/*
 * Allocate memory for the line of text
 */

    tf_point->value = (char *)Far_Malloc(strlen(atpoint) + 1);

    if (tf_point->value == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(tf_point->value, atpoint);

/*
 * See if it's the to: kludge. If it is, we want it at the top.
 * We make sure it looks like "To: " as well.
 */

    testing = atpoint;
    skipspace(testing);

    if (! strnicmp(testing, "to:", 3)) {
        if (strncmp(atpoint, "To: ", 4)) {      /* Yes: atpoint */

            testing += 3;
            skipspace(testing);

            (void)Far_Free(tf_point->value);

            (void)strcpy(new_address, "To: ");
            (void)strcat(new_address, testing);

            tf_point->value = (char *)Far_Malloc(strlen(new_address) + 1);

            if (tf_point->value == (char *)NULL) {
                (void)printf("I ran out of memory!\n");
                fcloseall();
                exit(Out_Of_Memory);
            }

            (void)strcpy(tf_point->value, new_address);
        }

        if (tf_first != (struct Text_File *)NULL) {
            tf_hold = tf_first;
            tf_first = tf_point;
            tf_point->next = tf_hold;
            return;
        }
    }

/*
 * Append the entry in the linked list.
 */

    tf_point->next = (struct Text_File *)NULL;

    if (tf_first == (struct Text_File *)NULL) {
        tf_first = tf_point;
    }
    else {
        tf_last->next = tf_point;
    }

    tf_last = tf_point;
}

/* **********************************************************************
   * We're through with the message text. Toss it.                      *
   *                                                                    *
   ********************************************************************** */

static void toss_text_linked_list(void)
{
    struct Text_File *next;

    tf_point = tf_first;

    while (tf_point) {
        next = tf_point->next;
        Far_Free(tf_point->value);
        Far_Free(tf_point);
        tf_point = next;
    }

    tf_first = tf_last = tf_point = (struct Text_File *)NULL;
}

/* **********************************************************************
   * Make a log entry.                                                  *
   *                                                                    *
   ********************************************************************** */

static void make_log_entry(char *fname,
    char *return_line,
    int the_size,
    BOOL good_to)
{
    char record[201];
    char sub_string[30];
    char hold_return[45];

    (void)strncpy(sub_string, message.subject, 25);
    sub_string[25] = (char)NULL;
    (void)strncpy(hold_return, return_line, 40);
    hold_return[40] = (char)NULL;

    (void)sprintf(record, "    %-40s Sub: %-25s\n", hold_return, sub_string);
    (void)fputs(record, file_log);
    (void)sprintf(record, "    %s   [%d bytes]\n", fname, the_size);
    (void)fputs(record, file_log);

    if (! good_to) {
        (void)sprintf(record, "   MESSAGE WAS BOUNCED to message %d\n",
            file_log, highest_mail);

        (void)fputs(record, file_log);
    }

    (void)fputs("\n", file_log);
}

/* **********************************************************************
   * Plug all kludge lines.                                             *
   *                                                                    *
   ********************************************************************** */

static void include_kludge(FILE *fout, int highest_move, BOOL good_to)
{
    char record[201];
    time_t the_time;

/*
 * The MSGID contains a unique number so that duplications can be
 * searched for. We use the highest message number in the move
 * directory and the current date and time. That should be fine.
 */

    the_time = time(NULL);

    if (strnicmp(area_tag, "none", 4)) {
        (void)sprintf(record, "%cAREA: %s\n", 0x01, area_tag);
        (void)fputs(record, fout);
    }

    (void)sprintf(record, "%cMSGID: %d:%d/%d.%d %08lx%c%c",
        0x01,
        message.originate_zone,
        message.originate_net,
        message.originate_node,
        message.originate_point,
        (unsigned long)the_time * (highest_move + 1),
        0x0d, 0x0a);

    (void)fputs(record, fout);

/*
 * See if it should be kludged as immediate and direct.
 * If the message is being bounced, however, don't include these.
 */

    if (mark_immediate && good_to) {
        (void)sprintf(record, "%cFLAGS IMM, DIR%c%c", 0x01, 0x0d, 0x0a);
        (void)fputs(record, fout);
    }

/*
 * Add the 'topt' and 'fmpt' kludges if needed
 */

    if (f_point != 0) {

        (void)sprintf(record, "%cFMPT %d%c%c",
            0x01, message.originate_point, 0x0d, 0x0a);

        (void)fputs(record, fout);
    }

    if (message.destination_point != 0) {

        (void)sprintf(record, "%cTOPT %d%c%c",
	    0x01, message.destination_point, 0x0d, 0x0a);

        (void)fputs(record, fout);
    }

/*
 * Add the 'INTL' kludge if needed
 */

    if (f_zone != message.destination_zone) {

        (void)sprintf(record, "%cINTL %d:%d/%d.%d %d:%d/%d.%d%c%c",
            0x01,
            message.destination_zone,
            message.destination_net,
            message.destination_node,
            message.destination_point,
            f_zone,
            f_net,
            f_node,
            f_point,
            0x0d, 0x0a);

        (void)fputs(record, fout);
    }
}

/* **********************************************************************
   * See if we should ignore this line of text.                         *
   * Return TRUE if we should else return FALSE.                        *
   *                                                                    *
   * If it's a to: that's addressed to uucp, then we don't want that!   *
   *                                                                    *
   * If it's a 'decap' command, set flag and return TRUE.               *
   *                                                                    *
   ********************************************************************** */

static BOOL exclude_this_line(char *atpoint)
{
    if ((strlen(atpoint) == 0) && last_line_blank)
        return(TRUE);

    if (! strnicmp(atpoint, "from:", 5))
        return(TRUE);

    if (! strnicmp(atpoint, "to", 2)) {
        atpoint += 2;
        skipspace(atpoint);

        if (*atpoint == ':') {
            atpoint++;
            skipspace(atpoint);

            if (! strnicmp(atpoint, "uucp@", 5)) {
                return(TRUE);
            }
        }
    }

/*
 * If we are supposed to decap the message, set the flag and return
 * a TRUE so that the decap request is not sent as a message line.
 */

    if (! strnicmp(atpoint, "decap", 5)) {
        decap_message = TRUE;
        return(TRUE);
    }

/*
 * We have a line we'll allow. Check to see if it's a blank line.
 * We only want a maximum of _ONE_ blank line in a message.
 */

    last_line_blank = (BOOL)(strlen(atpoint) == 0);

    m_point = m_first;

    while (m_point) {
        if (! strnicmp(atpoint, m_point->value1, strlen(m_point->value1))) {
            return(TRUE);
        }

        m_point = m_point->next;
    }

    return(FALSE);
}

/* **********************************************************************
   * Decapitalize the line that we're looking at.                       *
   *                                                                    *
   ********************************************************************** */

static void decap_this_line(struct Text_File *tf_point)
{
    char *atpoint, *where;
    int byte;

    atpoint = tf_point->value;

    if (strlen(atpoint) == 0)
        was_period = TRUE;

/*
 * Every character which follows a . gets set to lower case except
 * for the very first character which is left alone.
 */

    while (*atpoint) {
        if (was_period && isalpha(*atpoint)) {
            was_period = FALSE;
            atpoint++;
        }
        else if (*atpoint == '.' || *atpoint == '?' || *atpoint == '!') {
            was_period = TRUE;
            atpoint++;
        }
        else {
            byte = tolower(*atpoint);
            *atpoint = (char)byte;
            atpoint++;
        }
    }

/*
 * See if personal I should be set to uppercase.
 */

    atpoint = tf_point->value;

    where = strstr(atpoint, " i ");

    while (where != (char *)NULL) {
        where++;
        *where = 'I';
        where = strstr(atpoint, " i ");
    }

    where = strstr(atpoint, " i'll");

    while (where != (char *)NULL) {
        where++;
        *where = 'I';
        where = strstr(atpoint, " i'll");
    }

    where = strstr(atpoint, " i've");

    while (where != (char *)NULL) {
        where++;
        *where = 'I';
        where = strstr(atpoint, " i've");
    }

    where = strstr(atpoint, " i'm");

    while (where != (char *)NULL) {
        where++;
        *where = 'I';
        where = strstr(atpoint, " i'm");
    }
}

/* **********************************************************************
   * See if there is only 1 numeric in the call sign. Return TRUE or    *
   * FALSE depending.                                                   *
   *                                                                    *
   ********************************************************************** */

static BOOL test_call_sign(char *sign)
{
    unsigned char number_count;

    number_count = 0;

    while (*sign) {
        if (isdigit(*sign))
            number_count++;

        sign++;
    }

    return((BOOL)(number_count == 1));
}

/* **********************************************************************
   * We have what appears to be a message. Create a new *.MSG file and  *
   * examine the packet text file for addressing information.           *
   *                                                                    *
   * This function will be vastly different depending upon your Packet  *
   * Host BBS software.                                                 *
   *                                                                    *
   ********************************************************************** */

static void extract_message(char *atpoint)
{
    char *where, *npoint;
    char record[201];
    char call_sign[30], count;
    char subject[81];
    char path[101];
    char msg_file_name[101];
    char return_line[101];
    int the_day, the_month, the_year;
    time_t the_time;
    struct tm *local_time;
    FILE *msg_out;
    BOOL do_bail_out;
    BOOL no_path;
    BOOL good_to;
    int the_size;
    long where_at;
    unsigned char loop;

    if (want_diag)
        (void)printf("DIAG: Extracting message attempt...\n%s", atpoint);

    (void)time(&the_time);
    local_time = localtime(&the_time);

    the_year = local_time->tm_year;
    the_month = local_time->tm_mon;
    the_day = local_time->tm_mday;

    if (the_year > 1900)
        the_year -= 1900;

do_it_all_again:
    decap_message = FALSE;

    where = strstr(atpoint, "lines from");

    if (where == (char *)NULL) {
        if (want_diag) {
            (void)printf("DIAG: Can't find 'lines from'\n");
        }
        return;
    }

    where += 10;
    atpoint = where;
    skipspace(atpoint);

/*
 * Extract the destinations call sign.
 */

    count = 0;

    while (*atpoint && *atpoint != ' ' && count < 25)
        call_sign[count++] = *atpoint++;

    call_sign[count] = (char)NULL;

    if (! test_call_sign(call_sign)) {
        skipspace(atpoint);
        count = 0;

        while (*atpoint && *atpoint != ' ' && count < 25)
            call_sign[count++] = *atpoint++;

        call_sign[count] = (char)NULL;
    }

    if (want_diag)
        (void)printf("DIAG: call sign {%s}\n", call_sign);

/*
 * The next line should be the subject line
 */

    (void)fgets(record, 200, mail_file);

    if (feof(mail_file))
        return;

    atpoint = record;
    skipspace(atpoint);

    if (strnicmp(atpoint, "To:", 3)) {
        if (want_diag) {
            (void)printf("DIAG: 'to:' keyword missing:\n%s", atpoint);
        }
        return;
    }

/*
 * Extract the subject
 */

    count = 0;
    where = strstr(atpoint, "Re:");

    if (where == (char *)NULL) {
        if (want_diag) {
            (void)printf("DIAG: 're:' keyword missing:\n%s", atpoint);
        }

        return;
    }

    where += 4;
    atpoint = where;

    while (*atpoint && *atpoint != 0x0d && *atpoint != 0x0a && count < 80)
        subject[count++] = *atpoint++;

    subject[count] = (char)NULL;

    if (want_diag)
        (void)printf("DIAG: subject {%s}\n", subject);

/*
 * We search for R: in the next 5 lines.
 */

    where_at = ftell(mail_file);
    no_path = TRUE;

    for (loop = 0; loop < 5 && no_path; loop++) {
        (void)fgets(record, 200, mail_file);

        if (feof(mail_file)) {
            (void)fseek(mail_file, where_at, SEEK_SET);
            no_path = FALSE;
        }
        else {
            atpoint = record;
            skipspace(atpoint);

            if (! strnicmp(atpoint, "R:", 2)) {
                no_path = FALSE;
            }
        }
    }   

    if (no_path)
        (void)fseek(mail_file, where_at, SEEK_SET);

    if (! no_path) {
        count = 0;
        where = strstr(atpoint, "@:");

        if (where == (char *)NULL) {
            where = strchr(atpoint, '@');

            if (where == (char *)NULL) {
                return;
            }

            where++;
        }
        else {
            where += 2;
        }

        atpoint = where;
        skipspace(where);

/*
 * Extract the path.
 */

        while (*atpoint && *atpoint != ' ' && count < 100)
            path[count++] = *atpoint++;

        path[count] = (char)NULL;
    }
    else {
        (void)strcpy(path, host);
        where = strchr(path, '-');

        if (where != (char *)NULL) {
            *where = (char)NULL;
        }
    }

    if (want_diag)
        (void)printf("DIAG: path {%s}\n", path);

/*
 * Extract the text into a linked list
 */

    do_bail_out = FALSE;

    while (! do_bail_out) {
        if (! no_path) {
            (void)fgets(record, 200, mail_file);
        }
        else {
            no_path = FALSE;
        }

        if (! feof(mail_file)) {
            atpoint = record;
            npoint = record;
            skipspace(atpoint);

            if (*atpoint == '#') {
                do_bail_out = TRUE;
            }
            else {
                if (strstr(npoint, command_prompt) != (char *)NULL) {
                    do_bail_out = TRUE;
                }
                else if (! strnicmp(atpoint, "-|end|-", 7)) {
                    do_bail_out = TRUE;
                }
                else if (! exclude_this_line(atpoint)) {
                    plug_message_text(npoint);
                }
            }
        }
        else {
            do_bail_out = TRUE;
            plug_message_text(record);
        }
    }

/*
 * Check to see if the message has had a To: somewhere in it.  If
 * not, we want to send the message back into Packet because it can't
 * be delivered.  We will prepost a message text after the header
 * so that the Packet User will know what's going on.
 *
 * The address, by the way, must have both a @ and a . before it is
 * considered to be an address worth sending into Internet.
 */

    tf_point = tf_first;
    good_to = FALSE;

    while (tf_point && !good_to) {
        if (! strncmp(tf_point->value, "To: ", 4)) {
            if (strchr(tf_point->value, '@') != (char *)NULL) {
                if (strchr(tf_point->value, '.') != (char *)NULL) {
                    good_to = TRUE;
                }
            }
        }

        tf_point = tf_point->next;
    }

/*
 * MUST NOT destroy 'record' or 'atpoint' from now on in this function.
 */

    (void)strcpy(message.from, "PAK-UUCP");

    if (good_to) {
        (void)strcpy(message.to, "UUCP");
        (void)strcpy(message.subject, ".");
        (void)strncat(message.subject, subject, 70);
        message.subject[71] = (char)NULL;
    }
    else {
        (void)strcpy(message.to, "PACKET");
        (void)strcpy(message.subject, "Internet mail missing To: address");
    }

    (void)sprintf(message.date, "%s %02d %s %02d",
        num_to_day[zeller(the_day, the_month, the_year)],
        the_day,
        num_to_month[the_month],
        the_year);

    message.times = 0;
    message.cost = 0;
    message.reply = 0;

/*
 * Make the attribute
 */

    message.attribute = Fido_Local + Fido_Kill;

    if (want_hold) {
        message.attribute += Fido_Hold;
    }
    else {
        if (! good_to && hold_b_packet) {
            message.attribute += Fido_Hold;
        }
    }

    message.upwards_reply = 0;

    message.originate_zone = f_zone;
    message.originate_net = f_net;
    message.originate_node = f_node;
    message.originate_point = f_point;

    if (good_to) {
        message.destination_zone = g_zone;
        message.destination_net = g_net;
        message.destination_node = g_node;
        message.destination_point = g_point;
    }
    else {
        message.destination_zone = f_zone;
        message.destination_net = f_net;
        message.destination_node = f_node;
        message.destination_point = f_point;
    }

    (void)sprintf(msg_file_name,
        "%s%d.MSG",
        fidonet_directory,
        ++highest_mail);

    if ((msg_out = fopen(msg_file_name, "wb")) == (FILE *)NULL) {

        (void)printf("I was unable to create message file %s!\n",
            msg_file_name);

        fcloseall();
        exit(Cant_Create_MSG_File);
    }

    if (fwrite(&message, sizeof(struct fido_msg), 1, msg_out) != 1) {
        (void)printf("I was unable to write message file!\n");
        fcloseall();
        exit(Cant_Write_MSG_File);
    }

    if (want_kludge)
        include_kludge(msg_out, highest_mail, good_to);

/*
 * If the packet message bounced, offer the return: kludge now.
 * Then offer the packet user some information on what was wrong.
 */

    if (! good_to) {
        (void)sprintf(return_line, "return: %s@%s", call_sign, path);
        (void)fputs(return_line, msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)fputs("Packet User:  The following mail for ", msg_out);
        (void)fputs("Internet was not deliverable", msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)fputs("and was bounced automatically because ", msg_out);
        (void)fputs("the Gateway software could", msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)fputs("not find the Internet address anywhere ", msg_out);
        (void)fputs("in your message.  Be sure", msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)fputs("to place a  To: user@address.org address ", msg_out);
        (void)fputs("line somewhere in your", msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)fputs("message so that it will be delivered.      ", msg_out);
        (void)fputs("      - PAK-UUCP Ver. " VERSION, msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);
        (void)fputs("-=-=-=-=-=-=-=-=-=-=-=-=-=  :START:", msg_out);
        (void)fputs("  =-=-=-=-=-=-=-=-=-=-=-=-=-=-", msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);
    }

/*
 * Write the text now
 */

    tf_point = tf_first;
    the_size = 0;
    was_period = TRUE;

    while (tf_point) {
        if (decap_message) {
            decap_this_line(tf_point);
        }

        (void)fputs(tf_point->value, msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);
        the_size += (strlen(tf_point->value));

        if (want_diag) {
            printf(":%s\n", tf_point->value);
        }

        if (tf_point == tf_first) {             /* Blank line after to: */
            (void)fputc(0x0d, msg_out);
            (void)fputc(0x0a, msg_out);
        }

        tf_point = tf_point->next;
    }

/*
 * Put in the return address
 */

    if (good_to) {
        (void)fputs(" - Internet system: ", msg_out);
        (void)fputs("In your reply, please include ", msg_out);
        (void)fputs("the 'return:' kludge", msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)fputs("   below so that your message will ", msg_out);
        (void)fputs("be sent to the right Packet system.", msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)fputs("   Address your Internet mail reply to: ", msg_out);
        (void)fputs(reply_path, msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);

        (void)sprintf(return_line, "return: %s@%s", call_sign, path);
        (void)fputs(return_line, msg_out);
        (void)fputc(0x0d, msg_out);
        (void)fputc(0x0a, msg_out);
    }

    if (want_diag)
        (void)printf("DIAG: return {%s}\n", return_line);

    if (want_log)
        make_log_entry(msg_file_name, return_line, the_size, good_to);

    (void)fclose(msg_out);
    toss_text_linked_list();
    goto do_it_all_again;
}

/* **********************************************************************
   * Find the highest message number and return it.                     *
   *                                                                    *
   ********************************************************************** */

static short find_highest_message_number(char *directory)
{
    int result;
    short highest_message_number = 0;
    char directory_search[100];
    struct File_Block file_block;

/*
 * Build the directory name to search for, include \ if needed
 */

    (void)strcpy(directory_search, directory);

    if (directory[strlen(directory) - 1] != '\\')
        (void)strcat(directory, "\\");

    (void)strcat(directory_search, "*.MSG");

/*
 * See if we have at least one
 */

    result = Find_First(directory_search, &file_block, 0x16);

    if (! result) {
        if (atoi(file_block.Find_Name) > highest_message_number) {
            highest_message_number = atoi(file_block.Find_Name);
        }
    }

/*
 * Scan all messages until we know the highest message number
 */

    while (! result) {
        result = Find_Next(&file_block);

        if (! result) {
            if (atoi(file_block.Find_Name) > highest_message_number) {
                highest_message_number = atoi(file_block.Find_Name);
            }
        }
    }

/*
 * Return the value
 */

    return(highest_message_number);
}

/* **********************************************************************
   * Search the inbound message file for the start of the messages.     *
   *                                                                    *
   * When the start is found, we simply return, allowing mail to be     *
   * processed from this point onward. If we hit the end of file, we    *
   * simply return as well and allow the other functions to take care   *
   * of checking for end of file.                                       *
   *                                                                    *
   ********************************************************************** */

static void search_for_mail_start(void)
{
    char record[201], *atpoint;

    while (! feof(mail_file)) {
        (void)fgets(record, 200, mail_file);

        if (! feof(mail_file)) {
            atpoint = record;
            skipspace(atpoint);

            if (! strnicmp(atpoint, "-|start|-", 9)) {
                return;
            }
        }
    }
}

/* **********************************************************************
   * Process the inbound mail file.                                     *
   *                                                                    *
   ********************************************************************** */

static void process_inbound_mail(void)
{
    char record[201], *atpoint;

    highest_mail = find_highest_message_number(fidonet_directory);

    if (want_diag)
        (void)printf("DIAG: Highest in %s is %d\n",
            fidonet_directory,
            highest_mail);

    if ((mail_file = fopen(packet_file_name, "rt")) == (FILE *)NULL) {
        (void)printf("Cant re-open mail file: %s!\n", packet_file_name);
        fcloseall();
        exit(Cant_Open_Mail_File);
    }

    search_for_mail_start();

    while (! feof(mail_file)) {
        (void)fgets(record, 200, mail_file);

        if (! feof(mail_file)) {
            atpoint = record;
            skipspace(atpoint);

            if (*atpoint == '#') {
                if (strstr(atpoint, " lines from ") != (char *)NULL) {
                    extract_message(atpoint);
                }
            }
        }
    }

    (void)fclose(mail_file);

    if (! keep_packet) {
        (void)unlink(packet_file_name);
    }
}

/* **********************************************************************
   * Open the log file for append. If it doesn't exist, create it.      *
   *                                                                    *
   * If we can't create it, we plow through.                            *
   *                                                                    *
   ********************************************************************** */

static void open_append_create_log_file(void)
{
    time_t the_time;
    struct tm *local_time;
    char record[201];

    if ((file_log = fopen(log_path, "a+t")) == (FILE *)NULL) {
        if ((file_log = fopen(log_path, "wt")) == (FILE *)NULL) {
            (void)printf("Could not create log file: %s!\n", log_path);
            want_log = FALSE;
            return;
        }
    }

    (void)time(&the_time);
    local_time = localtime(&the_time);

    (void)sprintf(record, "%02d/%s/%02d - %02d:%02d:%02d\n",
        local_time->tm_mday,
        num_to_month[local_time->tm_mon],
        local_time->tm_year,
        local_time->tm_hour,
        local_time->tm_min,
        local_time->tm_sec);

    (void)fputs(record, file_log);
}

/* **********************************************************************
   * Build the reply path.                                              *
   *                                                                    *
   ********************************************************************** */

static void build_reply_path(void)
{
    (void)sprintf(reply_path, "packet@f%d.n%d.z%d.fidonet.org",
        f_node, f_net, f_zone);
}

/* **********************************************************************
   * Bounce the UUCP message.                                           *
   *                                                                    *
   ********************************************************************** */

static void bounce_uucp_message(FILE *msg_file)
{
    char record[201];
    int the_day, the_month, the_year;
    time_t the_time;
    struct tm *local_time;

    if (want_diag)
        (void)printf("DIAG: bounce UUCP message\n");

    (void)time(&the_time);
    local_time = localtime(&the_time);

    the_year = local_time->tm_year;
    the_month = local_time->tm_mon;
    the_day = local_time->tm_mday;

    if (the_year > 1900)
        the_year -= 1900;

    rewind(msg_file);

    (void)strcpy(message.from, "PAK-UUCP");
    (void)strcpy(message.to, "UUCP");
    (void)strcpy(message.subject, "Bounced packet mail");

    message.originate_zone = f_zone;
    message.originate_net = f_net;
    message.originate_node = f_node;
    message.originate_point = f_point;

    message.destination_zone = g_zone;
    message.destination_net = g_net;
    message.destination_node = g_node;
    message.destination_point = g_point;

    (void)sprintf(message.date, "%s %02d %s %02d",
        num_to_day[zeller(the_day, the_month, the_year)],
        the_day,
        num_to_month[the_month],
        the_year);

    message.times = 0;
    message.cost = 0;
    message.reply = 0;

/*
 * Make the attribute
 */

    message.attribute = Fido_Local + Fido_Kill;

    if (uucp_hold)
        message.attribute |= Fido_Hold;

    message.upwards_reply = 0;

/*
 * Update the header
 */

    if (fwrite(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
        (void)printf("I was unable to bounce a message file!\n");
        return;
    }

/*
 * Send the destination address
 */

    (void)sprintf(record, "To: %s", uucp_address);
    (void)fputs(record, msg_file);
    (void)fputc(0x0d, msg_file);
    (void)fputc(0x0a, msg_file);

/*
 * Don't forget the blank line now
 */

    (void)fputc(0x0d, msg_file);
    (void)fputc(0x0a, msg_file);

/*
 * Send the scolding.  Internet Users should know better.
 */

    (void)fputs("Internet User:  Your mail destined for the ", msg_file);
    (void)fputs("HAM Radio Packet domain", msg_file);
    (void)fputc(0x0d, msg_file);
    (void)fputc(0x0a, msg_file);

    (void)fputs("was automatically bounced because there was ", msg_file);
    (void)fputs("no valid destination address ", msg_file);
    (void)fputc(0x0d, msg_file);
    (void)fputc(0x0a, msg_file);

    (void)fputs("found in your message text.  Please be sure ", msg_file);
    (void)fputs("to include the 'return:'", msg_file);
    (void)fputc(0x0d, msg_file);
    (void)fputc(0x0a, msg_file);

    (void)fputs("kludge in your mail for Packet.  Somewhere ", msg_file);
    (void)fputs("in your message you", msg_file);
    (void)fputc(0x0d, msg_file);
    (void)fputc(0x0a, msg_file);

    (void)fputs("must put something like:   return: callsign@ ", msg_file);
    (void)fputs("callsign.others.others", msg_file);
    (void)fputc(0x0d, msg_file);
    (void)fputc(0x0a, msg_file);

    (void)fputs("-=-=-=-=-=-=-=-=-=-=-=-=-=  :START:", msg_file);
    (void)fputs("  =-=-=-=-=-=-=-=-=-=-=-=-=-=-", msg_file);
    (void)fputc(0x0d, msg_file);
    (void)fputc(0x0a, msg_file);

    ut_point = ut_first;

    while (ut_point) {
        (void)fputs(ut_point->value, msg_file);
        (void)fputc(0x0d, msg_file);
        (void)fputc(0x0a, msg_file);

        ut_point = ut_point->next;
    }

/*
 * Make a NULL and EOF just for fun. DO NOT CLOSE IT HERE.
 */

    (void)fputc(0, msg_file);
    (void)fputc(26, msg_file);
}

/* **********************************************************************
   * Deallocate the UUCP inbound message.                               *
   *                                                                    *
   ********************************************************************** */

static void free_uucp_message(void)
{
    struct UUCP_Text *next;

    ut_point = ut_first;

    while (ut_point) {
        next = ut_point->next;
        Far_Free(ut_point->value);
        Far_Free(ut_point);
        ut_point = next;
    }

    ut_first = ut_last = ut_point = (struct UUCP_Text *)NULL;
}

/* **********************************************************************
   * Here we send the message entirely.  Then we wait for a command     *
   * prompt before we return.                                           *
   *                                                                    *
   ********************************************************************** */

static BOOL send_packet_message(FILE *msg_file)
{
    char record[201];

    if (want_diag)
        (void)printf("DIAG: sending packet message from UUCP\n");

    if (want_log) {
        (void)sprintf(record, "   To HAM: %s\n   From Internet: %s\n",
            packet_destination,
            uucp_address);

        (void)fputs(record, file_log);
    }

/*
 * Send the "send to this HAM" command.
 */

    (void)sprintf(record, "s %s%c", packet_destination, 0x0d);
    print_buffer(record, tnc_port, want_diag);
    delay(100);

/*
 * Send the subject
 */

    (void)sprintf(record, "%s%c", message.subject, 0x0d);
    print_buffer(record, tnc_port, want_diag);

/*
 * NEED TO WAIT HERE FOR A RESPONSE THAT SAYS EITHER GOOD OR BAD ADDRESS!!!
 * If it's a bad address we bail-out and don't modify the message.  Sadly
 * we'll try again later?
 */

    delay(500);

/*
 * Send all lines now.
 */

    ut_point = ut_first;

    while (ut_point) {
        (void)sprintf(record, "%s%c", ut_point->value, 0x0d);
        print_buffer(record, tnc_port, want_diag);
        ut_point = ut_point->next;
        delay(100);
    }

/*
 * Send a /ex on a new line (just to be sure.)
 */

    (void)sprintf(record, "%c/ex%c", 0x0d, 0x0d);
    print_buffer(record, tnc_port, want_diag);

    if (! perform_uucp) {
        if (wait_for_command_prompt(TRUE)) {
            rewind(msg_file);

            message.attribute |= Fido_Sent;

            if (fwrite(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
                (void)printf("I was unable to 'SENT' a message file!\n");
                delay(500);
                return(TRUE);
            }

            delay(500);
            return(TRUE);
        }

        delay(500);
        return(FALSE);
    }
    else {
        rewind(msg_file);

        message.attribute |= Fido_Sent;

        if (fwrite(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {
            (void)printf("I was unable to 'SENT' a message file!\n");
            return(TRUE);
        }

        return(TRUE);
    }
}

/* **********************************************************************
   * Take the Internet address being offered and store it into the      *
   * string variable 'uucp_address[]'                                   *
   *                                                                    *
   * The address stops at the first space character or a ( character.   *
   *                                                                    *
   ********************************************************************** */

static void plug_uucp_from(char *atpoint)
{
    char *where;

    (void)strcpy(uucp_address, atpoint);

    where = strchr(uucp_address, ' ');

    if (where != (char *)NULL)
        *where = (char)NULL;

    where = strchr(uucp_address, '(');

    if (where != (char *)NULL)
        *where = (char)NULL;

    if (want_diag)
        (void)printf("DIAG: UUCP address: [%s]\n", uucp_address);
}

/* **********************************************************************
   * We have a return: kludge.  Plug it into the 'packet_destination[]' *
   * array if it looks good and return TRUE.  Else return FALSE.        *
   *                                                                    *
   * We take all of the return: up to the first space.                  *
   *                                                                    *
   ********************************************************************** */

static BOOL plug_uucp_return(char *atpoint)
{
    char *where, *search;
    BOOL any_good = FALSE;
    char ncount = 0;

    (void)strcpy(packet_destination, atpoint);

    where = strchr(packet_destination, ' ');

    if (where != (char *)NULL)
        *where = (char)NULL;

    if (want_diag)
        (void)printf("DIAG: packet_destination: [%s]\n", packet_destination);

    any_good = (BOOL)(strchr(packet_destination, '@') != (char *)NULL);

    if (! any_good)
        return(FALSE);

/*
 * There must be a single numeric value before the @ symbol
 */

    search = atpoint;
    ncount = 0;

    while (*search != '@') {
        if (*search >= '0' && *search <= '9') {
            ncount++;
        }
        search++;
    }

    if (ncount != 1)
        return(FALSE);

/*
 * There must be a single numeric value after the @ symbol
 */

    search++;
    ncount = 0;

    while (*search) {
        if (*search >= '0' && *search <= '9') {
            ncount++;
        }

        search++;
    }

    if (ncount != 1)
        return(FALSE);

    return(TRUE);
}

/* **********************************************************************
   * We store the line of UUCP inbound mail here.                       *
   *                                                                    *
   ********************************************************************** */

static void plug_uucp_line(char *atpoint)
{
    ut_point = (struct UUCP_Text *)Far_Malloc(sizeof(struct UUCP_Text));

    if (ut_point == (struct UUCP_Text *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }

    ut_point->value = (char *)Far_Malloc(strlen(atpoint) + 1);

    if (ut_point->value == (char *)NULL) {
        (void)printf("I ran out of memory!\n");
        fcloseall();
        exit(Out_Of_Memory);
    }                          

    (void)strcpy(ut_point->value, atpoint);

/*
 * Append the entry in the linked list.
 */

    ut_point->next = (struct UUCP_Text *)NULL;

    if (ut_first == (struct UUCP_Text *)NULL) {
        ut_first = ut_point;
    }
    else {
        ut_last->next = ut_point;
    }

    ut_last = ut_point;
}

/* **********************************************************************
   * Get a UUCP line.                                                   *
   *                                                                    *
   ********************************************************************** */

static void get_uucp_record(FILE *msg_file, char *record)
{
    char byte;

    while (! feof(msg_file)) {
        byte = (char)fgetc(msg_file);

        if (byte != 0x0a && byte != 0x0d) {
            *record++ = byte;
        }
        else if (byte == 0x0d) {
            *record++ = (char)NULL;
            return;
        }
    }

    *record++ = (char)NULL;
}

/* **********************************************************************
   * Read the UUCP message into memory, taking care to look for the     *
   * various bits of information we need like the From: address.  We    *
   * will return TRUE if we find a return: kludge else we will return   *
   * FALSE.                                                             *
   *                                                                    *
   * String variable 'uucp_address[n]' contains the "From:" string      *
   * after it has been processed.                                       *
   *                                                                    *
   ********************************************************************** */

static BOOL uucp_has_return(FILE *msg_file)
{
    char record[201], *atpoint;
    BOOL found_return;

    if (want_diag)
        (void)printf("DIAG: checking for return: in UUCP\n");

    found_return = FALSE;

    (void)strcpy(uucp_address, "Unknown Internet address!");

    while (! feof(msg_file)) {
        get_uucp_record(msg_file, record);

        atpoint = record;
        skipspace(atpoint);

        if (! strnicmp(atpoint, "From:", 5)) {
            atpoint += 5;
            skipspace(atpoint);
            plug_uucp_from(atpoint);
        }
        else if (! strnicmp(atpoint, "To:", 3)) {
        }
        else if (! strnicmp(atpoint, "Date:", 5)) {
        }
        else if (! strnicmp(atpoint, "return:", 7)) {
            atpoint += 7;
            skipspace(atpoint);
            found_return = plug_uucp_return(atpoint);

            if (! found_return) {
                plug_uucp_line(record);
            }
        }
        else if (*atpoint != 0x01) {
            plug_uucp_line(record);
        }
        else {
            /* Ignore read-in of ^A kludges */
        }
    }

    return(found_return);
}

/* **********************************************************************
   * See if we should process the message.                              *
   *                                                                    *
   ********************************************************************** */

static BOOL check_for_mail_from_uucp(char *directory, char *name)
{
    char directory_search[101];
    FILE *msg_file;
    BOOL from_uucp;

/*
 * Build the directory name to search for, include \ if needed
 */

    (void)strcpy(directory_search, directory);

    if (directory[strlen(directory) - 1] != '\\')
        (void)strcat(directory, "\\");

    (void)strcat(directory_search, name);

/*
 * Open it for a binary read
 */

    if ((msg_file = fopen(directory_search, "r+b")) == (FILE *)NULL) {

        (void)printf("I was unable to open message file %s!\n",
            directory_search);

        return(TRUE);
    }

/*
 * Get the header off of the message file
 */

    if (fread(&message, sizeof(struct fido_msg), 1, msg_file) != 1) {

        (void)printf("I was unable to read message file: %s!\n",
            directory_search);

        (void)fclose(msg_file);
        return(TRUE);
    }

/*
 * We process messages from UUCP which may or may not have
 * been tossed to Remote Access by the RA-UUCP package.
 */

    from_uucp = (BOOL)!strnicmp(message.from, "uucp", 4);

    if (! from_uucp)
        from_uucp = (BOOL)!strnicmp(message.from, ".uucp", 5);

/*
 * Selection for export to Packet is done by:
 *
 *      Must be addressed to PACKET
 *      Must not be marked as HOLD
 *      Must not be marked as SENT
 *      Must have a return: packet address
 *
 * If there is no packet address then we bounce it automatically
 */

    if (from_uucp) {
        if (! strnicmp(message.to, "packet", 6)) {
            if ((message.attribute & Fido_Hold) != Fido_Hold) {
                if ((message.attribute & Fido_Sent) != Fido_Sent) {
                    if (uucp_has_return(msg_file)) {
                        if (! send_packet_message(msg_file)) {
                            free_uucp_message();
                            (void)fclose(msg_file);
                            return(FALSE);
                        }
                    }
                    else {
                        bounce_uucp_message(msg_file);
                    }

                    free_uucp_message();
                }
            }
        }
    }

    (void)fclose(msg_file);
    return(TRUE);
}

/* **********************************************************************
   * Go through each message file in the scan directory and pass them   *
   * to a function which will see if they are from UUCP.  If they are   *
   * from UUCP, see if they are addressed to PACKET and have a return:  *
   * kludge in them.  If so, call the function which will send it and   *
   * then wait for the command prompt.                                  *
   *                                                                    *
   * If the message is from UUCP addressed to PACKET and does not have  *
   * the return: kludge, bound the message back to UUCP and, if the     *
   * configuration requires it, put the message on hold.                *
   *                                                                    *
   ********************************************************************** */

static void process_outbound_mail(char *directory)
{
    int result;
    char directory_search[101];
    struct File_Block file_block;

    (void)printf("Scanning for mail from UUCP to Packet...\n");

/*
 * Build the directory name to search for, include \ if needed
 */

    (void)strcpy(directory_search, directory);

    if (directory[strlen(directory) - 1] != '\\')
        (void)strcat(directory, "\\");

    (void)strcat(directory_search, "*.MSG");

/*
 * See if we have at least one
 */

    result = Find_First(directory_search, &file_block, 0x16);

    if (! result) {
        if (! check_for_mail_from_uucp(directory, file_block.Find_Name)) {
            result = TRUE;
        }
    }

/*
 * Scan all messages until we know the highest message number
 */

    while (! result) {
        result = Find_Next(&file_block);

        if (! result) {
            if (! check_for_mail_from_uucp(directory, file_block.Find_Name)) {
                result = TRUE;
            }
        }
    }
}

/* **********************************************************************
   * The main entry point.                                              *
   *                                                                    *
   ********************************************************************** */

void main(int argc, char *argv[])
{
    int loop;
    char *atpoint;
    BOOL connected;
    BOOL skip_connect;
    char record[101];
    char aborted;

    initialize();

    perform_uucp = FALSE;
    skip_connect = FALSE;

    say_hello();

    for (loop = 1; loop < argc; loop++) {
        if (! strnicmp(argv[loop], "/diag", 5)) {
            want_diag = TRUE;
        }
        else if (! strnicmp(argv[loop], "/com", 4)) {
            atpoint = argv[loop];
            atpoint += 4;
            tnc_port = atoi(atpoint);

            if (tnc_port > 3) {
                (void)printf("/com must be from 0 to 3!\n");
                fcloseall();
                exit(Bad_Com_Port_Number);
            }

            tnc_port_valid = TRUE;
        }
        else if (! strnicmp(argv[loop], "/skip", 5)) {
            skip_connect = TRUE;
        }
        else if (! strnicmp(argv[loop], "/uucp", 5)) {
            perform_uucp = TRUE;
        }
    }

    if (! tnc_port_valid) {
        (void)printf("You must supply a /com0 to /com3 command!\n");
        fcloseall();
        exit(Bad_Com_Port_Number);
    }

    extract_configuration();

    build_reply_path();

    if (want_log)
        open_append_create_log_file();

    if (skip_connect) {
        (void)strcpy(packet_file_name, "TEST.MIN");
        (void)printf("Processing skip file: TEST.MIN\n");
        process_inbound_mail();
        fcloseall();
        exit(0);
    }

    if (perform_uucp) {
        process_outbound_mail(fidonet_directory);
    }

    open_up_communications_port();
    check_the_tnc();
    open_up_mail_file();
    send_configuration();

/*
 * Attempt the connection.
 */

    connected = FALSE;
    aborted = FALSE;
    loop = 0;

    while (! connected && ! aborted && loop < connect_retry) {
        connected = make_connect_attempt(&aborted);
        loop++;
    }

    if (aborted) {
        (void)printf("Connect failure after %d tries: OPERATOR ABORTED\n",
            connect_retry);

        fcloseall();
        exit(Connect_Failure_Abort);
    }

    if (! connected) {
        (void)printf("Connect failure after %d tries\n", connect_retry);
        fcloseall();
        exit(Connect_Failure);
    }

    (void)printf("Connected to %s\n", host);

/*
 * Mark the MIN file to indicate that what follows should be the
 * start of the text to scan. This is done so that we don't start
 * looking for messages in the download file until this point on.
 */

    (void)sprintf(record, "%c%c-|start|-%c%c", 0x0d, 0x0a, 0x0d, 0x0a);
    (void)fputs(record, mail_file);

/*
 * Send access-bbs strings.
 */

    send_bbs_access_strings();

/*
 * Wait for the command prompt, performing string matching and
 * response as needed and indicated.
 */

    if (! wait_for_command_prompt(FALSE)) {
        (void)printf("Command prompt was never seen!\n");
        bail_out(No_Command_Prompt_Seen);
    }

    (void)printf("Have BBS command prompt.\n");

/*
 * Send the read-mail strings.
 */

    send_read_mail_strings();

/*
 * While we accumulate the mail, if any, we will check
 * for inactivity time-out and bail-out in any event.
 *
 * When the command prompt is seen again, we mark the end of
 * the inbound side of the process.
 */

    if (wait_for_command_prompt(TRUE)) {
        mark_end_of_inbound();
    }

/*
 * We have all of the inbound mail now sitting in a file.
 * Before we let the Packet Host go, let's transmit all of
 * the outbound mail that may be waiting to go out.
 */

    process_outbound_mail(fidonet_directory);

/*
 * Get the disconnection started.
 */

    send_disconnect_strings();

/*
 * Close up serial port after sending 'd'isconnect to TNC.
 */

    bail_out(Process_Mail);

/*
 * Close the inbound message file.
 */

    (void)fclose(mail_file);

/*
 * Process the inbound mail.
 */

    process_inbound_mail();

/*
 * We are finished.
 */

    if (want_log) {
        (void)fclose(file_log);
    }

    fcloseall();
    exit(No_Problem);
}

