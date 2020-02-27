/*********
  Rui Santos
  Complete project details at https://randomnerdtutorials.com
  Based on the NTP Client library example
*********/

#include <WiFi.h>
#include <NTPClient.h>
#include <WiFiUdp.h>
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_attr.h"
#include "esp_deep_sleep.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "apps/sntp/sntp.h"
// Libraries for SD card
#include "FS.h"
#include "SD.h"
#include <SPI.h>
#include <NTPClient.h>
#include <WiFiUdp.h>
#include <ESP32Ping.h>
         
#include <WiFiMulti.h>         // Built-in
#include <ESP32WebServer.h>    // https://github.com/Pedroalbuquerque/ESP32WebServer download and place in your Libraries folder
#include <ESPmDNS.h>
#include "Network.h"
#include "Sys_Variables.h"
#include "CSS.h"
#include <SDConfigFile.h>



///////////////////////////////////////////////////////////////
#define SD_CS 5
#define LED_GPIO_PIN                     5
#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)
uint8_t level = 0, channel = 1;
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP);
WiFiMulti wifiMulti;
ESP32WebServer server(80);
// Variables to save date and time
bool connect_to_ap = true;
bool initpromisquous = false;
bool promisquousactivate= false;
String formattedDate;
static wifi_country_t wifi_country = {.cc = "JP", .schan = 1, .nchan = 13}; //Most recent esp32 library struct
const char CONFIG_FILE[] = "example.cfg";
typedef struct {
  unsigned frame_ctrl: 16;
  unsigned duration_id: 16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl: 16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event)
{
  return ESP_OK;
}


void writeFile(fs::FS &fs, const char * path, const char * message) {
//  Serial.printf("Writing file: %s\n", path);
//
//  File file = fs.open(path, FILE_WRITE);
//  if (!file) {
//    Serial.println("Failed to open file for writing");
//    return;
//  }
//  if (file.print(message)) {
//    Serial.println("File written");
//  } else {
//    Serial.println("Write failed");
//  }
//  file.close();

}

// Append data to the SD card (DON'T MODIFY THIS FUNCTION)
void appendFile(fs::FS &fs, const char * path, const char * message, int n) {
  Serial.printf("Appending to file: %s\n", path);

  File file = fs.open(path, FILE_APPEND);
  if (!file) {
    Serial.println("Failed to open file for appending");
    return;
  }
  if (file.print(message)) {
    Serial.println("Message appended");
  } else {
    Serial.println("Append failed");
  }
  file.close();
}

// Append data to the SD card (DON'T MODIFY THIS FUNCTION)
void appendDataFile(fs::FS &fs, const char * path, const char * message, int n) {
  Serial.printf("Appending to file: %s\n", path);

  File file = fs.open(path, FILE_APPEND);
  if (!file) {
    Serial.println("Failed to open file for appending");
    return;
  }
  if (file.write((byte *)message,n )) {
    Serial.println("Message appended");
  } else {
    Serial.println("Append failed");
  }
  file.close();
}

void wifi_sniffer_init(void)
{
  ESP_ERROR_CHECK( nvs_flash_init() );
  tcpip_adapter_init();
  //tcpip_adapter_init();
  //ESP_ERROR_CHECK( esp_wifi_stop() );
  //ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  //wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  //ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  //ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  Serial.println("I'm before wifi_sniffer_packet_handler");
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  Serial.println("I'm after wifi_sniffer_packet_handler");

}

void wifi_sniffer_set_channel(uint8_t channel)
{
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch (type) {
    case WIFI_PKT_MGMT: return "MGMT";
    case WIFI_PKT_DATA: return "DATA";
    default:
    case WIFI_PKT_MISC: return "MISC";
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
  if (type != WIFI_PKT_MGMT)
    return;
  
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  uint8_t chipid[6];

  char msgtowrite[200];
  char datatowrite[23];

  //strncpy(datatowrite,&tm,8);
  //strncpy(datatowrite+8,&ppkt,1);
//  strncpy(datatowrite+9,hdr->addr1,6);
//  strncpy(datatowrite+9+6,hdr->addr2,6);
//  strncpy(datatowrite+9+12,hdr->addr3,6);

  int8_t rssi;
  unsigned long time0;
  char myip1[18];
  char myip2[18];
  char myip3[18];
  char comparestring[]="44:65:0d:34:75:4d";
  sprintf(myip1,"%02x:%02x:%02x:%02x:%02x:%02x",hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
          hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
  sprintf(myip2,"%02x:%02x:%02x:%02x:%02x:%02x",hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
        hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
  sprintf(myip3,"%02x:%02x:%02x:%02x:%02x:%02x",hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
  hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);
   Serial.println(sizeof comparestring);
  Serial.print(myip1);
  Serial.print(myip2);  
  Serial.print(myip3);
  Serial.println(sizeof time0);
  Serial.println("Size");
  Serial.println(sizeof rssi);
  Serial.println("Size of rssi");
  strncpy(datatowrite,(char*)(hdr->addr1),6);
  strncpy(datatowrite+6,(char*)(hdr->addr2),6);
  strncpy(datatowrite+12,(char*)(hdr->addr3),6);
  rssi = ppkt->rx_ctrl.rssi;
  time0 = timeClient.getEpochTime();
  Serial.print(time0);
  strncpy(datatowrite+12+6,(char*)(&rssi),1);
  strncpy(datatowrite+12+6+1,(char*)(&time0),4);
  Serial.println(timeClient.getFormattedDate());
  
  //Serial.print(datatowrite.lenght());
  
  sprintf(msgtowrite,
          "TS=%s, "         
          "RSSI=%02d,"
          " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
          " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
          " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
          timeClient.getFormattedDate().c_str(),

          ppkt->rx_ctrl.rssi,
          /* ADDR1 */
          hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
          hdr->addr1[3], hdr->addr1[4], hdr->addr1[5],
          /* ADDR2 */
          hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
          hdr->addr2[3], hdr->addr2[4], hdr->addr2[5],
          /* ADDR3 */
          hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
          hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]
         );
  printf(

"TS=%s, "         
    "RSSI=%02d,"
 " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
          " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
          " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",

          timeClient.getEpochTime(),
          

    ppkt->rx_ctrl.rssi,
    /* ADDR1 */
    hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
    hdr->addr1[3], hdr->addr1[4], hdr->addr1[5],
    /* ADDR2 */
    hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
    hdr->addr2[3], hdr->addr2[4], hdr->addr2[5],
    /* ADDR3 */
    hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
    hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]

  );
  if ((myip1 != "44:65:0d:34:75:4d") || (myip2 != "44:65:0d:34:75:4d") || (myip3 != "44:65:0d:34:75:4d") ){
    
    appendDataFile(SD, "/data.bin", datatowrite,23);  
    }if(strcmp(myip1,comparestring)==0 || strcmp(myip2,comparestring)==0 || strcmp(myip3,comparestring)==0){
      Serial.print("Trovatooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo");
      }
  



}

////////////////////////////////////////////////////////////////
// Replace with your network credentials
const char* ssid     = "YOUR_SSID";
const char* password = "YOUR_PASSWORD";

// Define NTP Client to get time

String dayStamp;
String timeStamp;

void setup() {
  // Initialize Serial Monitor
  Serial.begin(115200);
    uint8_t mac2[6];
  system_efuse_read_mac(mac2);
  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  SD.begin(SD_CS);  
   if(SD.begin(SD_CS)) {
     SD_present = true; 
  }
  if(!SD.begin(SD_CS)) {
    Serial.println("Card Mount Failed");
    SD_present = false; 
    return;
  }
  uint8_t cardType = SD.cardType();
  if(cardType == CARD_NONE) {
    Serial.println("No SD card attached");
    return;
  }
  Serial.println("Initializing SD card...");
  if (!SD.begin(SD_CS)) {
    Serial.println("ERROR - SD card initialization failed!");
    return;    // init failed
  }

  // If the data.txt file doesn't exist
  // Create a file on the SD card and write the data labels
 File file = SD.open("/data.bin");
  if(!file) {
    Serial.println("File doens't exist");
    Serial.println("Creating file...");
   
  }
  else {
    Serial.println("File already exists");  
  }
  file.close();
  
  // Print local IP address and start web server
  Serial.println("");
  Serial.println("WiFi connected.");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());

  // Initialize a NTPClient to get time
  timeClient.begin();
  // Set offset time in seconds to adjust for your timezone, for example:
  // GMT +1 = 3600
  // GMT +8 = 28800
  // GMT -1 = -3600
  // GMT 0 = 0
  timeClient.setTimeOffset(28800+3600);
  timeClient.forceUpdate();
  Serial.println(F("Card initialised... file access enabled..."));
 
  server.on("/",         HomePage);
  server.on("/download", File_Download);
  server.on("/upload",   File_Upload);
  server.on("/fupload",  HTTP_POST,[](){ server.send(200);}, handleFileUpload);
  server.on("/stream",   File_Stream);
  server.on("/delete",   File_Delete);
  server.on("/dir",      SD_dir);
  server.on("/capture",  Start_Capture);
  
  ///////////////////////////// End of Request commands
  server.begin();
  Serial.println("HTTP server started");
  
 

}
void loop() {

  if (connect_to_ap == true){
    server.handleClient(); 
      // Serial.print("   server.handleClient() ");
  }
  if (connect_to_ap == false){
      Serial.print("initpromisquous TRUE: ");
     WiFi.disconnect();
  WiFi.mode(WIFI_OFF);

  delay(1000);

  pinMode(LED_GPIO_PIN, OUTPUT);
    wifi_sniffer_init();
    initpromisquous = true;
  }
  if (initpromisquous == true){
     Serial.print("lAST STEP: ");
    formattedDate = timeClient.getFormattedDate();
  Serial.println(formattedDate);
  
  // Extract date
  int splitT = formattedDate.indexOf("T");
  dayStamp = formattedDate.substring(0, splitT);
  Serial.print("DATE: ");
  Serial.println(dayStamp);
  // Extract time
  timeStamp = formattedDate.substring(splitT + 1, formattedDate.length() - 1);
  Serial.print("HOUR: ");
  Serial.println(timeStamp);
  delay(1000);
  if (digitalRead(LED_GPIO_PIN) == LOW)
    digitalWrite(LED_GPIO_PIN, HIGH);
  else
    digitalWrite(LED_GPIO_PIN, LOW);
  vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
  wifi_sniffer_set_channel(channel);
  channel = (channel % WIFI_CHANNEL_MAX) + 1;
  }
//bool initpromisquous = false;
//bool promisquousactivate= false;
  // while(!timeClient.update()) {
  //   timeClient.forceUpdate();
  // }
  // The formattedDate comes with the following format:
  // 2018-05-28T16:00:13Z
  // We need to extract date and time
  
}

void HomePage(){
  SendHTML_Header();
  webpage += F("<a href='/download'><button>Download</button></a>");
  webpage += F("<a href='/upload'><button>Upload</button></a>");
  webpage += F("<a href='/stream'><button>Stream</button></a>");
  webpage += F("<a href='/delete'><button>Delete</button></a>");
  webpage += F("<a href='/dir'><button>Directory</button></a>");
  webpage += F("<a href='/capture'><button>StartCapture</button></a>");
  append_page_footer();
  SendHTML_Content();
  SendHTML_Stop(); // Stop is needed because no content length was sent
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void File_Download(){ // This gets called twice, the first pass selects the input, the second pass then processes the command line arguments
  if (server.args() > 0 ) { // Arguments were received
    if (server.hasArg("download")) SD_file_download(server.arg(0));
  }
  else SelectInput("Enter filename to download","download","download");
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void SD_file_download(String filename){
  if (SD_present) { 
    File download = SD.open("/"+filename);
    if (download) {
      server.sendHeader("Content-Type", "text/text");
      server.sendHeader("Content-Disposition", "attachment; filename="+filename);
      server.sendHeader("Connection", "close");
      server.streamFile(download, "application/octet-stream");
      download.close();
      
    } else ReportFileNotPresent("download"); 
  } else ReportSDNotPresent();
  
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void File_Upload(){
  Serial.println("File upload stage-1");
  append_page_header();
  webpage += F("<h3>Select File to Upload</h3>"); 
  webpage += F("<FORM action='/fupload' method='post' enctype='multipart/form-data'>");
  webpage += F("<input class='buttons' style='width:40%' type='file' name='fupload' id = 'fupload' value=''><br>");
  webpage += F("<br><button class='buttons' style='width:10%' type='submit'>Upload File</button><br>");
  webpage += F("<a href='/'>[Back]</a><br><br>");
  append_page_footer();
  Serial.println("File upload stage-2");
  server.send(200, "text/html",webpage);
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
File UploadFile; 
void handleFileUpload(){ // upload a new file to the Filing system
  Serial.println("File upload stage-3");
  HTTPUpload& uploadfile = server.upload(); // See https://github.com/esp8266/Arduino/tree/master/libraries/ESP8266WebServer/srcv
                                            // For further information on 'status' structure, there are other reasons such as a failed transfer that could be used
  if(uploadfile.status == UPLOAD_FILE_START)
  {
    Serial.println("File upload stage-4");
    String filename = uploadfile.filename;
    if(!filename.startsWith("/")) filename = "/"+filename;
    Serial.print("Upload File Name: "); Serial.println(filename);
    SD.remove(filename);                         // Remove a previous version, otherwise data is appended the file again
    UploadFile = SD.open(filename, FILE_WRITE);  // Open the file for writing in SPIFFS (create it, if doesn't exist)
    filename = String();
  }
  else if (uploadfile.status == UPLOAD_FILE_WRITE)
  {
    Serial.println("File upload stage-5");
    if(UploadFile) UploadFile.write(uploadfile.buf, uploadfile.currentSize); // Write the received bytes to the file
  } 
  else if (uploadfile.status == UPLOAD_FILE_END)
  {
    if(UploadFile)          // If the file was successfully created
    {                                    
      UploadFile.close();   // Close the file again
      Serial.print("Upload Size: "); Serial.println(uploadfile.totalSize);
      webpage = "";
      append_page_header();
      webpage += F("<h3>File was successfully uploaded</h3>"); 
      webpage += F("<h2>Uploaded File Name: "); webpage += uploadfile.filename+"</h2>";
      webpage += F("<h2>File Size: "); webpage += file_size(uploadfile.totalSize) + "</h2><br>"; 
      append_page_footer();
      server.send(200,"text/html",webpage);
    } 
    else
    {
      ReportCouldNotCreateFile("upload");
    }
  }
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void SD_dir(){
  if (SD_present) { 
    File root = SD.open("/");
    if (root) {
      root.rewindDirectory();
      SendHTML_Header();
      webpage += F("<h3 class='rcorners_m'>SD Card Contents</h3><br>");
      webpage += F("<table align='center'>");
      webpage += F("<tr><th>Name/Type</th><th style='width:20%'>Type File/Dir</th><th>File Size</th></tr>");
      printDirectory("/",0);
      webpage += F("</table>");
      SendHTML_Content();
      root.close();
    }
    else 
    {
      SendHTML_Header();
      webpage += F("<h3>No Files Found</h3>");
    }
    append_page_footer();
    SendHTML_Content();
    SendHTML_Stop();   // Stop is needed because no content length was sent
  } else ReportSDNotPresent();
}
void Start_Capture(){
  connect_to_ap = false;
  
  }
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void printDirectory(const char * dirname, uint8_t levels){
  File root = SD.open(dirname);
  #ifdef ESP8266
  root.rewindDirectory(); //Only needed for ESP8266
  #endif
  if(!root){
    return;
  }
  if(!root.isDirectory()){
    return;
  }
  File file = root.openNextFile();
  while(file){
    if (webpage.length() > 1000) {
      SendHTML_Content();
    }
    if(file.isDirectory()){
      Serial.println(String(file.isDirectory()?"Dir ":"File ")+String(file.name()));
      webpage += "<tr><td>"+String(file.isDirectory()?"Dir":"File")+"</td><td>"+String(file.name())+"</td><td></td></tr>";
      printDirectory(file.name(), levels-1);
    }
    else
    {
      //Serial.print(String(file.name())+"\t");
      webpage += "<tr><td>"+String(file.name())+"</td>";
      Serial.print(String(file.isDirectory()?"Dir ":"File ")+String(file.name())+"\t");
      webpage += "<td>"+String(file.isDirectory()?"Dir":"File")+"</td>";
      int bytes = file.size();
      String fsize = "";
      if (bytes < 1024)                     fsize = String(bytes)+" B";
      else if(bytes < (1024 * 1024))        fsize = String(bytes/1024.0,3)+" KB";
      else if(bytes < (1024 * 1024 * 1024)) fsize = String(bytes/1024.0/1024.0,3)+" MB";
      else                                  fsize = String(bytes/1024.0/1024.0/1024.0,3)+" GB";
      webpage += "<td>"+fsize+"</td></tr>";
      Serial.println(String(fsize));
    }
    file = root.openNextFile();
  }
  file.close();
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void File_Stream(){
  if (server.args() > 0 ) { // Arguments were received
    if (server.hasArg("stream")) SD_file_stream(server.arg(0));
  }
  else SelectInput("Enter a File to Stream","stream","stream");
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void SD_file_stream(String filename) { 
  if (SD_present) { 
    File dataFile = SD.open("/"+filename, FILE_READ); // Now read data from SD Card 
    Serial.print("Streaming file: "); Serial.println(filename);
    if (dataFile) { 
      if (dataFile.available()) { // If data is available and present 
        String dataType = "application/octet-stream"; 
        if (server.streamFile(dataFile, dataType) != dataFile.size()) {Serial.print(F("Sent less data than expected!")); } 
      }
      dataFile.close(); // close the file: 
    } else ReportFileNotPresent("Cstream");
  } else ReportSDNotPresent(); 
}   
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void File_Delete(){
  if (server.args() > 0 ) { // Arguments were received
    if (server.hasArg("delete")) SD_file_delete(server.arg(0));
  }
  else SelectInput("Select a File to Delete","delete","delete");
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void SD_file_delete(String filename) { // Delete the file 
  if (SD_present) { 
    SendHTML_Header();
    File dataFile = SD.open("/"+filename, FILE_READ); // Now read data from SD Card 
    Serial.print("Deleting file: "); Serial.println(filename);
    if (dataFile)
    {
      if (SD.remove("/"+filename)) {
        Serial.println(F("File deleted successfully"));
        webpage += "<h3>File '"+filename+"' has been erased</h3>"; 
        webpage += F("<a href='/delete'>[Back]</a><br><br>");
        
      }
      else
      { 
        webpage += F("<h3>File was not deleted - error</h3>");
        webpage += F("<a href='delete'>[Back]</a><br><br>");
      }
    } else ReportFileNotPresent("delete");
    append_page_footer(); 
    SendHTML_Content();
    SendHTML_Stop();
  } else ReportSDNotPresent();
} 
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void SendHTML_Header(){
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate"); 
  server.sendHeader("Pragma", "no-cache"); 
  server.sendHeader("Expires", "-1"); 
  server.setContentLength(CONTENT_LENGTH_UNKNOWN); 
  server.send(200, "text/html", ""); // Empty content inhibits Content-length header so we have to close the socket ourselves. 
  append_page_header();
  server.sendContent(webpage);
  webpage = "";
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void SendHTML_Content(){
  server.sendContent(webpage);
  webpage = "";
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void SendHTML_Stop(){
  server.sendContent("");
  server.client().stop(); // Stop is needed because no content length was sent
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void SelectInput(String heading1, String command, String arg_calling_name){
  SendHTML_Header();
  webpage += F("<h3>"); webpage += heading1 + "</h3>"; 
  webpage += F("<FORM action='/"); webpage += command + "' method='post'>"; // Must match the calling argument e.g. '/chart' calls '/chart' after selection but with arguments!
  webpage += F("<input type='text' name='"); webpage += arg_calling_name; webpage += F("' value=''><br>");
  webpage += F("<type='submit' name='"); webpage += arg_calling_name; webpage += F("' value=''><br><br>");
  append_page_footer();
  SendHTML_Content();
  SendHTML_Stop();
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void ReportSDNotPresent(){
  SendHTML_Header();
  webpage += F("<h3>No SD Card present</h3>"); 
  webpage += F("<a href='/'>[Back]</a><br><br>");
  append_page_footer();
  SendHTML_Content();
  SendHTML_Stop();
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void ReportFileNotPresent(String target){
  SendHTML_Header();
  webpage += F("<h3>File does not exist</h3>"); 
  webpage += F("<a href='/"); webpage += target + "'>[Back]</a><br><br>";
  append_page_footer();
  SendHTML_Content();
  SendHTML_Stop();
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void ReportCouldNotCreateFile(String target){
  SendHTML_Header();
  webpage += F("<h3>Could Not Create Uploaded File (write-protected?)</h3>"); 
  webpage += F("<a href='/"); webpage += target + "'>[Back]</a><br><br>";
  append_page_footer();
  SendHTML_Content();
  SendHTML_Stop();
}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
String file_size(int bytes){
  String fsize = "";
  if (bytes < 1024)                 fsize = String(bytes)+" B";
  else if(bytes < (1024*1024))      fsize = String(bytes/1024.0,3)+" KB";
  else if(bytes < (1024*1024*1024)) fsize = String(bytes/1024.0/1024.0,3)+" MB";
  else                              fsize = String(bytes/1024.0/1024.0/1024.0,3)+" GB";
  return fsize;
}
