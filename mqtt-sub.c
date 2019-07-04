/*
 * Copyright (c) 2014, Texas Instruments Incorporated - http://www.ti.com/
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \addtogroup cc26xx-web-demo
 * @{
 *
 * \file
 *   MQTT/IBM cloud service client for the CC26XX web demo.
 */
/*---------------------------------------------------------------------------*/
#include "contiki.h"
#include "net/routing/routing.h"
#include "mqtt.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-icmp6.h"
#include "sys/etimer.h"
#include "sys/ctimer.h"
#include "lib/sensors.h"
#include "dev/button-hal.h"
#include "board-peripherals.h"
#include "cc26xx-web-demo.h"
#include "dev/leds.h"
#include "mqtt-sub.h"
#include "httpd-simple.h"

#include <string.h>
#include <strings.h>
#include "AES-GCM-Decrypt.h"

/*---------------------------------------------------------------------------*/
/*
 * IBM server: messaging.quickstart.internetofthings.ibmcloud.com
 * (184.172.124.189) mapped in an NAT64 (prefix 64:ff9b::/96) IPv6 address
 * Note: If not able to connect; lookup the IP address again as it may change.
 *
 * If the node has a broker IP setting saved on flash, this value here will
 * get ignored
 */
static const char *broker_ip = "bbbb::a00:27ff:fe71:f6e1";
/*---------------------------------------------------------------------------*/
/*
 * A timeout used when waiting for something to happen (e.g. to connect or to
 * disconnect)
 */
#define STATE_MACHINE_PERIODIC     (CLOCK_SECOND >> 3)
/*---------------------------------------------------------------------------*/
/* Provide visible feedback via LEDS during various states */
/* When connecting to broker */
#define CONNECTING_LED_DURATION    (CLOCK_SECOND >> 3)

/* Each time we try to publish */
#define PUBLISH_LED_ON_DURATION    (CLOCK_SECOND)
/*---------------------------------------------------------------------------*/
/* Connections and reconnections */
#define RETRY_FOREVER              0xFF
#define RECONNECT_INTERVAL         (CLOCK_SECOND * 2)

/*
 * Number of times to try reconnecting to the broker.
 * Can be a limited number (e.g. 3, 10 etc) or can be set to RETRY_FOREVER
 */
#define RECONNECT_ATTEMPTS         5
#define CONNECTION_STABLE_TIME     (CLOCK_SECOND * 5)
#define NEW_CONFIG_WAIT_INTERVAL   (CLOCK_SECOND * 20)
static struct timer connection_life;
static uint8_t connect_attempt;
/*---------------------------------------------------------------------------*/
/* Various states */
static uint8_t state;
#define MQTT_CLIENT_STATE_INIT            0
#define MQTT_CLIENT_STATE_REGISTERED      1
#define MQTT_CLIENT_STATE_CONNECTING      2
#define MQTT_CLIENT_STATE_CONNECTED       3
#define MQTT_CLIENT_STATE_PUBLISHING      4
#define MQTT_CLIENT_STATE_DISCONNECTED    5
#define MQTT_CLIENT_STATE_NEWCONFIG       6
#define MQTT_LED_CHANGE_EVENT             7
#define MQTT_CLIENT_STATE_CONFIG_ERROR 0xFE
#define MQTT_CLIENT_STATE_ERROR        0xFF
/*---------------------------------------------------------------------------*/
/* Maximum TCP segment size for outgoing segments of our socket */
#define MQTT_CLIENT_MAX_SEGMENT_SIZE    32
/*---------------------------------------------------------------------------*/
/*
 * Buffers for Client ID and Topic.
 * Make sure they are large enough to hold the entire respective string
 *
 * d:quickstart:status:EUI64 is 32 bytes long
 * iot-2/evt/status/fmt/json is 25 bytes
 * We also need space for the null termination
 */
#define BUFFER_SIZE 64
#define PAYLOAD_SIZE 512
static char client_id[BUFFER_SIZE];
static char pub_topic[BUFFER_SIZE];
static char sub_topic[BUFFER_SIZE];
/*---------------------------------------------------------------------------*/
/*
 * The main MQTT buffers.
 * We will need to increase if we start publishing more data.
 */
#define APP_BUFFER_SIZE 512
static struct mqtt_connection conn;
static unsigned char app_buffer[APP_BUFFER_SIZE];
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
static struct mqtt_message *msg_ptr = 0;
static struct etimer publish_periodic_timer;
static struct ctimer ct;
static unsigned char *buf_ptr;
static uint16_t seq_nr_value = 0;
/*---------------------------------------------------------------------------*/
static uip_ip6addr_t def_route;
/*---------------------------------------------------------------------------*/
/* Parent RSSI functionality */
extern int def_rt_rssi;
/*---------------------------------------------------------------------------*/
const static cc26xx_web_demo_sensor_reading_t *reading;
/*---------------------------------------------------------------------------*/
mqtt_client_config_t *conf;
/*---------------------------------------------------------------------------*/
PROCESS(mqtt_client_process, "CC26XX MQTT Client");
/*---------------------------------------------------------------------------*/
char *publish_topic;
char publish_payload[PAYLOAD_SIZE];
char decrpyted_payload[PAYLOAD_SIZE];
int flags = 0;
int pub_flag = 0;
uint16_t ch_len = 0;
/*---------------------------------------------------------------------------*/
static void
publish_led_off(void *d)
{
  leds_off(CC26XX_WEB_DEMO_STATUS_LED);
}
/*---------------------------------------------------------------------------*/

///////////////////////////////////////////////////////////////////////////////
//  IOT-LAB
//  This function is the handler that is called after a message of a subscribed
//  topic is received.
///////////////////////////////////////////////////////////////////////////////
static void
pub_handler(const char *topic, uint16_t topic_len, const uint8_t *chunk,
            uint16_t chunk_len)
{
  printf("MQTT: Pub Handler: topic='%s' (len=%u), chunk_len=%u\n", topic, topic_len,
      chunk_len);

  publish_topic = (char *)topic;
  ch_len = chunk_len;
  
  //strcpy(publish_payload, (char *)chunk);
  //memcpy(buf_ptr, message, sizeof(message));
  memcpy(publish_payload, (char *)chunk, chunk_len);
  //main_decrypt((unsigned char *)publish_payload, (unsigned char *)decrpyted_payload, chunk_len);
 
  main_decrypt((unsigned char *)publish_payload, (unsigned char *)decrpyted_payload, chunk_len);
   
  printf("Publish Topic: %s\n", publish_topic);
  printf("Publish Payload: %s\n", decrpyted_payload);
 
  state = MQTT_LED_CHANGE_EVENT;
  flags = 1;
  
  /* If we don't like the length, ignore */
  //if(topic_len >= 14 || chunk_len != 1) {
    //printf("MQTT: Incorrect topic or chunk len. Ignored\n");
    //return;
  //}
}
/*---------------------------------------------------------------------------*/
static void
mqtt_event(struct mqtt_connection *m, mqtt_event_t event, void *data)
{
  switch(event) {
  case MQTT_EVENT_CONNECTED: {
    printf("MQTT: APP - Application has a MQTT connection\n");
    timer_set(&connection_life, CONNECTION_STABLE_TIME);
    state = MQTT_CLIENT_STATE_CONNECTED;
    break;
  }
  case MQTT_EVENT_DISCONNECTED: {
    printf("MQTT: APP - MQTT Disconnect. Reason %u\n", *((mqtt_event_t *)data));

    /* Do nothing if the disconnect was the result of an incoming config */
    if(state != MQTT_CLIENT_STATE_NEWCONFIG) {
      state = MQTT_CLIENT_STATE_DISCONNECTED;
      process_poll(&mqtt_client_process);
    }
    break;
  }
  case MQTT_EVENT_PUBLISH: {
    msg_ptr = data;

    /* Implement first_flag in publish message? */
    if(msg_ptr->first_chunk) {
      msg_ptr->first_chunk = 0;
      printf("MQTT: APP - Application received a publish on topic '%s'. Payload "
          "size is %i bytes. Content:\n\n",
          msg_ptr->topic, msg_ptr->payload_length);
    }


    pub_handler(msg_ptr->topic, strlen(msg_ptr->topic), msg_ptr->payload_chunk,
                msg_ptr->payload_length);
    break;
  }
  case MQTT_EVENT_SUBACK: {
    printf("MQTT: APP - Application is subscribed to topic successfully\n");
    break;
  }
  case MQTT_EVENT_UNSUBACK: {
    printf("MQTT: APP - Application is unsubscribed to topic successfully\n");
    break;
  }
  case MQTT_EVENT_PUBACK: {
    printf("MQTT: APP - Publishing complete.\n");
    break;
  }
  default:
    printf("MQTT: APP - Application got a unhandled MQTT event: %i\n", event);
    break;
  }
}
/*---------------------------------------------------------------------------*/
///////////////////////////////////////////////////////////////////////////////
///
/// IOT-LAB: Set the topic on which you want to publish here
///
///////////////////////////////////////////////////////////////////////////////
static int
construct_pub_topic(void)
{
  int len = snprintf(pub_topic, BUFFER_SIZE, "sensors/%s",
                     conf->event_type_id);

  /* len < 0: Error. Len >= BUFFER_SIZE: Buffer too small */
  if(len < 0 || len >= BUFFER_SIZE) {
    printf("MQTT: Pub Topic: %d, Buffer %d\n", len, BUFFER_SIZE);
    return 0;
  }

  return 1;
}
/*---------------------------------------------------------------------------*/
///////////////////////////////////////////////////////////////////////////////
///
/// IOT-LAB: Set the topic on which you want to subscribe here
///
///////////////////////////////////////////////////////////////////////////////
static int
construct_sub_topic(void)
{
  int len = snprintf(sub_topic, BUFFER_SIZE, "control/%s",
                     conf->cmd_type);

  /* len < 0: Error. Len >= BUFFER_SIZE: Buffer too small */
  if(len < 0 || len >= BUFFER_SIZE) {
    printf("MQTT: Sub Topic: %d, Buffer %d\n", len, BUFFER_SIZE);
    return 0;
  }

  return 1;
}
/*---------------------------------------------------------------------------*/
static int
construct_client_id(void)
{
  int len = snprintf(client_id, BUFFER_SIZE, "d:%s:%s:%02x%02x%02x%02x%02x%02x",
                     conf->org_id, conf->type_id,
                     linkaddr_node_addr.u8[0], linkaddr_node_addr.u8[1],
                     linkaddr_node_addr.u8[2], linkaddr_node_addr.u8[5],
                     linkaddr_node_addr.u8[6], linkaddr_node_addr.u8[7]);

  /* len < 0: Error. Len >= BUFFER_SIZE: Buffer too small */
  if(len < 0 || len >= BUFFER_SIZE) {
    printf("MQTT: Client ID: %d, Buffer %d\n", len, BUFFER_SIZE);
    return 0;
  }

  return 1;
}
/*---------------------------------------------------------------------------*/
static void
update_config(void)
{
  if(construct_client_id() == 0) {
    /* Fatal error. Client ID larger than the buffer */
    state = MQTT_CLIENT_STATE_CONFIG_ERROR;
    return;
  }

  if(construct_sub_topic() == 0) {
    /* Fatal error. Topic larger than the buffer */
    state = MQTT_CLIENT_STATE_CONFIG_ERROR;
    return;
  }

  if(construct_pub_topic() == 0) {
    /* Fatal error. Topic larger than the buffer */
    state = MQTT_CLIENT_STATE_CONFIG_ERROR;
    return;
  }

  /* Reset the counter */
  seq_nr_value = 0;

  state = MQTT_CLIENT_STATE_INIT;

  /*
   * Schedule next timer event ASAP
   *
   * If we entered an error state then we won't do anything when it fires.
   *
   * Since the error at this stage is a config error, we will only exit this
   * error state if we get a new config.
   */
  etimer_set(&publish_periodic_timer, 0);

  return;
}
/*---------------------------------------------------------------------------*/
static int
init_config()
{
  /* Populate configuration with default values */
  memset(conf, 0, sizeof(mqtt_client_config_t));

  memcpy(conf->org_id, CC26XX_WEB_DEMO_DEFAULT_ORG_ID, 10);
  memcpy(conf->auth_token, CC26XX_WEB_DEMO_DEFAULT_AUTH_TOKEN, 12);
  memcpy(conf->type_id, CC26XX_WEB_DEMO_DEFAULT_TYPE_ID, 7);
  memcpy(conf->event_type_id, CC26XX_WEB_DEMO_DEFAULT_EVENT_TYPE_ID, 7);
  memcpy(conf->broker_ip, broker_ip, strlen(broker_ip));
  memcpy(conf->cmd_type, CC26XX_WEB_DEMO_DEFAULT_SUBSCRIBE_CMD_TYPE, 1);

  conf->broker_port = CC26XX_WEB_DEMO_DEFAULT_BROKER_PORT;
  conf->pub_interval = CC26XX_WEB_DEMO_DEFAULT_PUBLISH_INTERVAL * 2;
  
  return 1;
}

static void
subscribe(void)
{
  /* Publish MQTT topic in IBM quickstart format */
  mqtt_status_t status;

  status = mqtt_subscribe(&conn, NULL, sub_topic, MQTT_QOS_LEVEL_0);

  printf("MQTT: APP - Subscribing!\n");
  if(status == MQTT_STATUS_OUT_QUEUE_FULL) {
    printf("MQTT: APP - Tried to subscribe but command queue was full!\n");
  }
}
/*---------------------------------------------------------------------------*/
///////////////////////////////////////////////////////////////////////////////
///
/// IOT-LAB: The publish function is executed periodically. Change the payload
/// to the data you want to send.
///
///////////////////////////////////////////////////////////////////////////////

static void
publish(void)
{
  /* Publish MQTT topic in IBM quickstart format */
  int len;
  int total_len = 0;
  int remaining = APP_BUFFER_SIZE;
  char def_rt_str[64];

  seq_nr_value++;
  for (int j = 0; j < APP_BUFFER_SIZE; j++) {
    app_buffer[j] = 0;
  }
  buf_ptr = app_buffer;

  len = snprintf((char *)buf_ptr, remaining,
                 "{"
                 "\"d\":{"
                 "\"myName\":\"%s\","
                 "\"Seq #\":%d,"
                 "\"Uptime (sec)\":%lu",
                 BOARD_STRING, seq_nr_value, clock_seconds());
  total_len += len;
  if(len < 0 || len >= remaining) {
    printf("Buffer too short. Have %d, need %d + \\0\n", remaining, len);
    return;
  }

  remaining -= len;
  buf_ptr += len;

  /* Put our Default route's string representation in a buffer */
  memset(def_rt_str, 0, sizeof(def_rt_str));
  cc26xx_web_demo_ipaddr_sprintf(def_rt_str, sizeof(def_rt_str),
                                 uip_ds6_defrt_choose());

  len = snprintf((char *)buf_ptr, remaining, ",\"Def Route\":\"%s\",\"RSSI (dBm)\":%d",
                 def_rt_str, def_rt_rssi);
  total_len += len;
  printf("%d : total len", total_len);
  if(len < 0 || len >= remaining) {
    printf("Buffer too short. Have %d, need %d + \\0\n", remaining, len);
    return;
  }
  remaining -= len;
  buf_ptr += len;

  memcpy(&def_route, uip_ds6_defrt_choose(), sizeof(uip_ip6addr_t));

  for(reading = cc26xx_web_demo_sensor_first();
      reading != NULL; reading = reading->next) {
    if(reading->publish && reading->raw != CC26XX_SENSOR_READING_ERROR) {
      len = snprintf((char *)buf_ptr, remaining,
                     ",\"%s (%s)\":%s", reading->descr, reading->units,
                     reading->converted);
      total_len += len;
      if(len < 0 || len >= remaining) {
        printf("Buffer too short. Have %d, need %d + \\0\n", remaining, len);
        return;
      }
      remaining -= len;
      buf_ptr += len;
    }
  }
    printf("%d : total len", total_len);
  len = snprintf((char *)buf_ptr, remaining, "}}");
  printf("%d : total len", total_len);
  total_len += len;
  if(len < 0 || len >= remaining) {
    printf("Buffer too short. Have %d, need %d + \\0\n", remaining, len);
    return;
  }

  snprintf(pub_topic, BUFFER_SIZE, "sensors/%s",
                     conf->event_type_id);


  mqtt_publish(&conn, NULL, pub_topic, (unsigned char*)app_buffer,
               strlen((char *)app_buffer), MQTT_QOS_LEVEL_0, MQTT_RETAIN_OFF);

   //main_encrpyt(app_buffer, encrpyt_app_buffer, total_len);
   //printf("The app buffer is %s", app_buffer);
  // printf("\n");

   //mqtt_publish(&conn, NULL, pub_topic, encrpyt_app_buffer,
   //           strlen((char *)encrpyt_app_buffer), MQTT_QOS_LEVEL_0, MQTT_RETAIN_OFF);

  total_len = 0;
  printf("MQTT: APP - Publish!\n");


}
/*---------------------------------------------------------------------------*/
static void
connect_to_broker(void)
{
  /* Connect to MQTT server */
  mqtt_status_t conn_attempt_result = mqtt_connect(&conn, conf->broker_ip,
                                                   conf->broker_port,
                                                   conf->pub_interval * 3);

  if(conn_attempt_result == MQTT_STATUS_OK) {
    state = MQTT_CLIENT_STATE_CONNECTING;
  } else {
    state = MQTT_CLIENT_STATE_CONFIG_ERROR;
  }
}
/*---------------------------------------------------------------------------*/
static void
state_machine(void)
{
  switch(state) {
  case MQTT_CLIENT_STATE_INIT:
    /* If we have just been configured register MQTT connection */
    mqtt_register(&conn, &mqtt_client_process, client_id, mqtt_event,
                  MQTT_CLIENT_MAX_SEGMENT_SIZE);

	#ifdef DEBUG
	printf("State-Machine: MQTT Client Initialized\n");
    #endif
    	
      if(strlen(conf->auth_token) == 0) {
        printf("MQTT: User name set, but empty auth token\n");
        state = MQTT_CLIENT_STATE_ERROR;
        break;
      } else {
        mqtt_set_username_password(&conn, conf->org_id,
                                   conf->auth_token);
      }
    

    /* _register() will set auto_reconnect. We don't want that. */
    conn.auto_reconnect = 0;
    connect_attempt = 1;

    /*
     * Wipe out the default route so we'll republish it every time we switch to
     * a new broker
     */
    memset(&def_route, 0, sizeof(def_route));

    state = MQTT_CLIENT_STATE_REGISTERED;
    printf("MQTT: Init\n");
    /* Continue */
  case MQTT_CLIENT_STATE_REGISTERED:
  
    #ifdef DEBUG
	printf("State-Machine: MQTT Client Registered\n");
    #endif
	
    if(uip_ds6_get_global(ADDR_PREFERRED) != NULL) {
      /* Registered and with a public IP. Connect */
      printf("MQTT: Registered. Connect attempt %u\n", connect_attempt);
      connect_to_broker();
    }
    etimer_set(&publish_periodic_timer, CC26XX_WEB_DEMO_NET_CONNECT_PERIODIC);
    return;
    break;
  case MQTT_CLIENT_STATE_CONNECTING:
  
    #ifdef DEBUG
	printf("State-Matchine: MQTT Client Connecting\n");
    #endif
	
    //leds_on(CC26XX_WEB_DEMO_STATUS_LED);
    ctimer_set(&ct, CONNECTING_LED_DURATION, publish_led_off, NULL);
    /* Not connected yet. Wait */
    printf("MQTT: Connecting (%u)\n", connect_attempt);
    break;
  case MQTT_CLIENT_STATE_CONNECTED:
  
    #ifdef DEBUG
	printf("MQTT Client Connected");
    #endif
	
    /* Don't subscribe unless we are a registered device */
#ifdef DEACTIVATE_SUB
	state = MQTT_CLIENT_STATE_PUBLISHING;
#endif
    /* Continue */
  case MQTT_CLIENT_STATE_PUBLISHING:
    /* If the timer expired, the connection is stable. */
	
	#ifdef DEBUG
	printf("State-Machine: MQTT Client Publishing\n");
    #endif
	
    if(timer_expired(&connection_life)) {
      /*
       * Intentionally using 0 here instead of 1: We want RECONNECT_ATTEMPTS
       * attempts if we disconnect after a successful connect
       */
      connect_attempt = 0;
    }
 
    if(mqtt_ready(&conn) && conn.out_buffer_sent) {
      /* Connected. Publish */
      if(state == MQTT_CLIENT_STATE_CONNECTED) {
		  
		#ifdef DEBUG
	    printf("MQTT Client subscribing");
        #endif
        subscribe();
        state = MQTT_CLIENT_STATE_PUBLISHING; 
        pub_flag = 1;        
      } else {
        leds_on(CC26XX_WEB_DEMO_STATUS_LED);
        ctimer_set(&ct, PUBLISH_LED_ON_DURATION, publish_led_off, NULL);
        publish();
      }
	  
      //sends publish data after 60 seconds
      //other data have interval of 20 seconds
      if(pub_flag == 1) {
        leds_on(CC26XX_WEB_DEMO_STATUS_LED);
        ctimer_set(&ct, PUBLISH_LED_ON_DURATION, publish_led_off, NULL);
        publish();
        etimer_set(&publish_periodic_timer, CC26XX_WEB_DEMO_DEFAULT_PUBLISH_INTERVAL/1.5);
        pub_flag = 0;
      }
      else {
        etimer_set(&publish_periodic_timer, conf->pub_interval);
      }
      
      printf("MQTT: Publishing\n");
      /* Return here so we don't end up rescheduling the timer */
      return;
    } else {
      /*
       * Our publish timer fired, but some MQTT packet is already in flight
       * (either not sent at all, or sent but not fully ACKd).
       *
       * This can mean that we have lost connectivity to our broker or that
       * simply there is some network delay. In both cases, we refuse to
       * trigger a new message and we wait for TCP to either ACK the entire
       * packet after retries, or to timeout and notify us.
       */
      printf("MQTT: Publishing... (MQTT state=%d, q=%u)\n", conn.state,
          conn.out_queue_full);
    }

    break;
	
  case MQTT_LED_CHANGE_EVENT:
    
	printf("Entering the LED state Machine\n");
	printf("Publish Topic: %s\n", publish_topic);
	printf("Publish Payload: %s\n", decrpyted_payload);
	
    
	if(strcmp(publish_topic,"control/leds") == 0 && strcmp((char *)decrpyted_payload,"LED_ON") == 0) {
	   #ifdef DEBUG
     	printf("State-Machine: LED ON Subscriber\n");
        memcpy(decrpyted_payload, 0, ch_len);
 
       #endif
       leds_on(CC26XX_WEB_DEMO_STATUS_RED_LED);
    } 
    if(strcmp(publish_topic,"control/leds") == 0 && strcmp((char *)decrpyted_payload,"LED_OFF") == 0) {
	   #ifdef DEBUG
     	printf("State-Machine: LED OFF Subscriber\n");
        memcpy(decrpyted_payload, 0, ch_len);
       #endif
       leds_off(CC26XX_WEB_DEMO_STATUS_RED_LED);
    } 
	
	state = MQTT_CLIENT_STATE_PUBLISHING;
	
	flags = 0;
	
	return;
	break;
	
  case MQTT_CLIENT_STATE_DISCONNECTED:
  
    printf("MQTT: Disconnected\n");
    if(connect_attempt < RECONNECT_ATTEMPTS ||
       RECONNECT_ATTEMPTS == RETRY_FOREVER) {
      /* Disconnect and backoff */
      clock_time_t interval;
      mqtt_disconnect(&conn);
      connect_attempt++;

      interval = connect_attempt < 3 ? RECONNECT_INTERVAL << connect_attempt :
        RECONNECT_INTERVAL << 3;

      printf("MQTT: Disconnected. Attempt %u in %lu ticks\n", connect_attempt, interval);

      etimer_set(&publish_periodic_timer, interval);

      state = MQTT_CLIENT_STATE_REGISTERED;
      return;
    } else {
      /* Max reconnect attempts reached. Enter error state */
      state = MQTT_CLIENT_STATE_ERROR;
      printf("MQTT: Aborting connection after %u attempts\n", connect_attempt - 1);
    }
    break;
  case MQTT_CLIENT_STATE_NEWCONFIG:
    /* Only update config after we have disconnected or in the case of an error */
    if(conn.state == MQTT_CONN_STATE_NOT_CONNECTED || conn.state == MQTT_CONN_STATE_ERROR) {
      update_config();
      printf("MQTT: New config\n");

      /* update_config() scheduled next pass. Return */
      return;
    }
    break;
  case MQTT_CLIENT_STATE_CONFIG_ERROR:
    /* Idle away. The only way out is a new config */
    printf("MQTT: Bad configuration.\n");
    return;
  case MQTT_CLIENT_STATE_ERROR:
  default:
    //leds_on(CC26XX_WEB_DEMO_STATUS_LED);
    /*
     * 'default' should never happen.
     *
     * If we enter here it's because of some error. Stop timers. The only thing
     * that can bring us out is a new config event
     */
    printf("MQTT: Default case: State=0x%02x\n", state);
    return;
  }

  /* If we didn't return so far, reschedule ourselves */
  etimer_set(&publish_periodic_timer, STATE_MACHINE_PERIODIC);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mqtt_client_process, ev, data)
{

  PROCESS_BEGIN();

  printf("CC26XX MQTT Client Process\n");

  conf = &cc26xx_web_demo_config.mqtt_config;
  if(init_config() != 1) {
    PROCESS_EXIT();
  }
  update_config();

  /* Main loop */
  while(1) {

    PROCESS_YIELD();

    if(ev == button_hal_release_event) {
      button_hal_button_t *btn = (button_hal_button_t *)data;

      if(btn->unique_id == CC26XX_WEB_DEMO_MQTT_PUBLISH_TRIGGER) {
        if(state == MQTT_CLIENT_STATE_ERROR) {
          connect_attempt = 1;
          state = MQTT_CLIENT_STATE_REGISTERED;
        }
      }
    }

    if(ev == httpd_simple_event_new_config) {
      /*
       * Schedule next pass in a while. When HTTPD sends us this event, it is
       * also in the process of sending the config page. Wait a little before
       * reconnecting, so as to not cause congestion.
       */
      etimer_set(&publish_periodic_timer, NEW_CONFIG_WAIT_INTERVAL);
    }

    if((ev == PROCESS_EVENT_TIMER && data == &publish_periodic_timer) ||
ev == PROCESS_EVENT_POLL || flags == 1 ||
       ev == cc26xx_web_demo_publish_event ||
       (ev == button_hal_release_event &&
        ((button_hal_button_t *)data)->unique_id ==
        CC26XX_WEB_DEMO_MQTT_PUBLISH_TRIGGER)) {
      state_machine();
    }

    if(ev == cc26xx_web_demo_load_config_defaults) {
      init_config();
      etimer_set(&publish_periodic_timer, NEW_CONFIG_WAIT_INTERVAL);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
/**
 * @}
 */
