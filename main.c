#include <platform.h>
#include <stdint.h>
#include <stdlib.h>
#include <printf.h>
#include <string.h>
#include <time.h>

#include "phy.h"
#include "soft_timer.h"
#include "event.h"

#ifdef IOTLAB_M3
#include "lps331ap.h"
#include "isl29020.h"
#endif
#include "iotlab_uid.h"
#include "mac_csma.h"
#include "phy.h"
#include "iotlab_i2c.h"

#include "iotlab_uid_num_hashtable.h"

// choose channel in [11-26]
#define CHANNEL 22
#define RADIO_POWER PHY_POWER_0dBm

#define ADDR_BROADCAST 0xFFFF

// UART callback function
static void char_rx(handler_arg_t arg, uint8_t c);
static void handle_cmd(handler_arg_t arg);

// timer alarm function
static void alarm(handler_arg_t arg);
static soft_timer_t tx_timer;
#define BLINK_PERIOD soft_timer_s_to_ticks(1)

/* Global variables */
// print help every second
volatile int8_t print_help  = 1;
volatile int8_t leds_active = 1;

int rank = 999;

// test

#ifdef IOTLAB_M3
/**
 * Sensors
 */
static void temperature_sensor()
{
    int16_t value;
    lps331ap_read_temp(&value);
    printf("Chip temperature measure: %f\n", 42.5 + value / 480.0);
}


static void light_sensor()
{
    float value = isl29020_read_sample();
    printf("Luminosity measure: %f lux\n", value);
}


static void pressure_sensor()
{
    uint32_t value;
    lps331ap_read_pres(&value);
    printf("Pressure measure: %f mabar\n", value / 4096.0);
}
#endif


/**
 * Node UID
 */
static void print_node_uid()
{
    uint16_t node_uid = iotlab_uid();
    struct node node = node_from_uid(node_uid);
    printf("Current node uid: %04x (%s-%u)\n",
            node_uid, node.type_str, node.num);
}


/**
 * Control Node interaction
 */

static void print_cn_time()
{
    // Query control node time
    struct soft_timer_timeval time;
    if (iotlab_get_time(&time)) {
        printf("Error while getting Control node time\n");
        return;
    }

    time_t timestamp = (time_t)time.tv_sec;
    struct tm *local_time = gmtime(&timestamp);
    char date_str[64];
    strftime(date_str, (sizeof date_str), "%Y-%m-%d %H:%M:%S", local_time);

    printf("Control Node time: %u.%06u. Date is: UTC %s.%06u\n",
            time.tv_sec, time.tv_usec, date_str, time.tv_usec);
}


/*
 * Radio config
 */
static void send_packet()
{
    uint16_t ret;
    static uint8_t num = 0;

    static char packet[PHY_MAX_TX_LENGTH - 4];  // 4 for mac layer
    uint16_t length;
    // max pkt length <= max(cc2420, cc1101)
    snprintf(packet, sizeof(packet), "Hello World!: %u", num++);
    length = 1 + strlen(packet);

    ret = mac_csma_data_send(ADDR_BROADCAST, (uint8_t *)packet, length);

    printf("\nradio > ");
    if (ret != 0)
        printf("Packet sent\n");
    else
        printf("Packet sent failed\n");
}

static void request_temp_measures(){
    uint16_t ret;
    static char packet[PHY_MAX_TX_LENGTH - 4];
    uint16_t length;

    snprintf(packet, sizeof(packet), "10");

    length = 1 + strlen(packet);
    ret = mac_csma_data_send(ADDR_BROADCAST, (uint8_t *)packet, length);

    if (ret != 0){
        printf("Request broadcasted");
    }else{
        printf("Request Broadcast Failed");
    }
}

static void forward_packet(char packet_sent[], uint16_t packet_length, int sender_rank){
    uint16_t ret;
    char packet[PHY_MAX_TX_LENGTH - 4];
    int packet_type = packet_sent[0] - '0';
    snprintf(packet, sizeof(packet), "%d%d%s", packet_type, sender_rank, packet_sent);
    ret = mac_csma_data_send(ADDR_BROADCAST, (uint8_t *) packet, packet_length);

    if (ret != 0){
        printf("Packet forwarded: %s", packet);
    }else{
        printf("Packet forwarding failed");
    }
}


static void send_big_packet()
{
    uint16_t ret;
    static uint8_t num = 0;

    static char packet[PHY_MAX_TX_LENGTH - 4];  // 4 for mac layer
    static char pluspack[40]="012345678901234567890123456789012345678\0";
    uint16_t length;

    snprintf(packet, sizeof(packet), "Big Hello World!: %u %s",num++, pluspack);
    length = 1 + strlen(packet);

    ret = mac_csma_data_send(ADDR_BROADCAST, (uint8_t *)packet, length);

    printf("\nradio > ");
    if (ret != 0)
        printf("Big packet sent\n");
    else
        printf("Big packet sent failed\n");
}


/* Reception of a radio message */
void mac_csma_data_received(uint16_t src_addr,
        const uint8_t *data, uint8_t length, int8_t rssi, uint8_t lqi)
{
    // disable help message after receiving one packet
    int sender_rank;
    print_help = 0;
    struct node src_node = node_from_uid(src_addr);
    // char test = (const char*) data[0];]
    char message[PHY_MAX_TX_LENGTH - 4];
    strcpy(message, (const char*) data);
    sender_rank = message[1] - '0';


    if (message[0] == '1' && sender_rank < rank && rssi > -60){
        printf("ASC: cuRrent rank: %d rcv: %s\n",rank , message);
        rank = sender_rank + 1;
        forward_packet(message, length, rank);
        printf("Got packet (TEMP MEASUREMENT) from %x (%s-%u). Len: %u Rssi: %d: '%s'\n",
            src_addr, src_node.type_str, src_node.num,
            length, rssi, (const char*)data);

        // WAIT FOR SOMETIME AND THEN FORWARD A PACKET CONTAINING TEMPERATURES MEASURES ...
        printf("sleeping\n");
        int i = 0;
        int j = 0;
        for(i = 0; i < 2000; i++){
          for(j = 0; j < 2000; j++);
        }
        printf("waking-up\n");

        // SEND TEMPATURE
        uint16_t node_uid = iotlab_uid();
        struct node ownnode = node_from_uid(node_uid);
        static char packet_b[PHY_MAX_TX_LENGTH - 4];
        char prefix[] = {'2', rank};
        char suffix[] = {ownnode.type_str[1],ownnode.num};
        char str_temp[20];

        int16_t value;
        lps331ap_read_temp(&value);
        float temperature = 42.5 + value / 480.0;
        sprintf(str_temp, "%f", temperature);

        char temp_packet[24];
        memcpy(temp_packet, prefix, 2 * sizeof(char));
        memcpy(temp_packet + 2, str_temp, 20 * sizeof(char));
        memcpy(temp_packet + 22, suffix, 2 * sizeof(char));

        snprintf(packet_b, sizeof(packet_b), temp_packet);

        length = 1 + strlen(packet_b);
        ret = mac_csma_data_send(ADDR_BROADCAST, (uint8_t *)packet_b, length);
        if (ret != 0){
            printf("Request broadcasted");
        }else{
            printf("Request Broadcast Failed");
        }

    }else if (message[0] == '2' && rank < sender_rank && rssi > -60){
        printf("DESC: current rank: %d rcv: %s", rank, message);
        forward_packet(message, length, rank - 1);

        if(rank == '0'){
          char node_type = message[22];
          char node_num = message[23];
          int rcv_rank = message[1];

          char tmp_buff[20];
          memcpy(tmp_buff, message + 2, 20 * sizeof(char));
          float rcv_temp = atof(tmp_buff);

          printf("Receive from node m%c-%d (Rank: %c): %f °C", node_type, node_num, rcv_rank, rcv_temp);
        }

        /* code */
    }else{
        printf("\nradio > ");
        printf("Got packet from %x (%s-%u). Len: %u Rssi: %d: '%s'\n",
            src_addr, src_node.type_str, src_node.num,
            length, rssi, (const char*)data);
    }
    handle_cmd((handler_arg_t) '\n');
}


/**
 * Leds action
 */
static void leds_action()
{
    printf("\nleds > ");
    if (leds_active) {
        // The alarm timer looses the hand
        leds_active = 0;
        // Switch off the LEDs
        leds_off(LED_0 | LED_1 | LED_2);
        printf("off\n");
    } else {
        // The alarm timer takes the hand
        leds_active = 1;
        printf("blinking ??\n");
    }
}


/*
 * HELP
 */
static void print_usage()
{
    printf("\n\nIoT-LAB Simple ? Demo program CANAL %d.\n", CHANNEL);
    printf("Type command\n");
    printf("\th:\tprint this help\n");
#ifdef IOTLAB_M3
    printf("\tt:\ttemperature measure\n");
    printf("\tl:\tluminosity measure\n");
    printf("\tp:\tpressure measure\n");
#endif
    printf("\tu:\tprint node uid\n");
    printf("\td:\tread current date using control_node\n");
    printf("\ts:\tsend a radio packet\n");
    printf("\tb:\tsend a big radio packet\n");
    printf("\te:\ttoggle leds blinking\n");
    printf("\tz:\tbroadcasts temparature request\n");
    printf("\tn:\tset up as 'puit'\n");
    printf("\tr:\tprint the node rank\n");
    if (print_help)
        printf("\n Type Enter to stop printing this help\n");
}


static void hardware_init()
{
    // Openlab platform init
    platform_init();
    event_init();
    soft_timer_init();

    // Switch off the LEDs
    leds_off(LED_0 | LED_1 | LED_2);

    // Uart initialisation
    uart_set_rx_handler(uart_print, char_rx, NULL);

#ifdef IOTLAB_M3
    // ISL29020 light sensor initialisation
    isl29020_prepare(ISL29020_LIGHT__AMBIENT, ISL29020_RESOLUTION__16bit,
            ISL29020_RANGE__16000lux);
    isl29020_sample_continuous();

    // LPS331AP pressure sensor initialisation
    lps331ap_powerdown();
    lps331ap_set_datarate(LPS331AP_P_12_5HZ_T_12_5HZ);
#endif

    // Init csma Radio mac layer
    mac_csma_init(CHANNEL, RADIO_POWER);

    // Init control_node i2c
    iotlab_i2c_init();

    // Initialize a openlab timer
    soft_timer_set_handler(&tx_timer, alarm, NULL);
    soft_timer_start(&tx_timer, BLINK_PERIOD, 1);
}


static void handle_cmd(handler_arg_t arg)
{
    switch ((char) (uint32_t) arg) {
#ifdef IOTLAB_M3
        case 't':
            temperature_sensor();
            break;
        case 'l':
            light_sensor();
            break;
        case 'p':
            pressure_sensor();
            break;
#endif
        case 'u':
            print_node_uid();
            break;
        case 'd':
            print_cn_time();
            break;
        case 's':
            send_packet();
            break;
        case 'b':
            send_big_packet();
            break;
        case 'e':
            leds_action();
            break;
        case '\n':
            printf("\ncmd > ");
            break;
        case 'z':
            request_temp_measures();
            break;
        case 'n':
            rank = 0;
            break;
        case 'r':
            printf("The node rank is: %d", rank);
            break;
        case 'h':
        default:
            print_usage();
            break;
    }
}


int main()
{
    hardware_init();
    platform_run();
    return 0;
}


/* Reception of a char on UART and store it in 'cmd' */
static void char_rx(handler_arg_t arg, uint8_t c)
{
    // disable help message after receiving char
    print_help = 0;
    event_post_from_isr(EVENT_QUEUE_APPLI, handle_cmd,
            (handler_arg_t)(uint32_t) c);
}


static void alarm(handler_arg_t arg)
{
    // if (leds_active)
        // leds_toggle(LED_0 | LED_1 | LED_2);

    /* Print help before getting first real \n */
    if (print_help) {
        event_post(EVENT_QUEUE_APPLI, handle_cmd, (handler_arg_t) 'h');
        event_post(EVENT_QUEUE_APPLI, handle_cmd, (handler_arg_t) '\n');
    }
}
