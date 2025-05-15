// Imported Arduino libraries
#include <LiquidCrystal_I2C.h>
#include <mcp_can.h>
#include <SPI.h>

// Homemade libraries
#include "AES_128.h"
#include "ECDH.h"
#include "Utilities.h"

// Helpful defines
#define AVR_MEGA_CS 53
#define CAN0_INT 2
#define _OPENDOOR "OPENDOOR"
#define _CHANGE_SEED "chanSEED"
#define _LOCKDOWN "LOCKDOWN"
#define _HEARTBEAT "HEARTBEA"
#define _LOCKDOOR "LOCKDOOR"

// CAN network interface variables
MCP_CAN CAN0(AVR_MEGA_CS);
long unsigned int rxId;
unsigned char len = 0;      
unsigned char rxBuf[8];
char msgString[128];                        // Array to store serial buffer for easy formatting

// set the LCD number of columns and rows
int lcdColumns = 16;
int lcdRows = 2;
String messageStatic = "";
String messageToScroll = "";

// set LCD address, number of columns and rows
LiquidCrystal_I2C lcd(0x27, lcdColumns, lcdRows);  

// state machine variables
unsigned char burst = 0;
unsigned char networkLockDown = 0;  
unsigned char iteration = 0;
unsigned char failsafe = 0;

static bool changetoSlave = false;
static bool isSEEDrequestFulfilled = false; 
static bool isAliceSent = false;
static bool isNetworkInLockDown = false;

// Encryption algorithm variables
long unsigned int encryptedFrame = 0;
unsigned char initialKey[17] = "Initial Keysssss";
unsigned char encryptedMessage[17];

// ECDH variables with sugestive names for better tracking
Point G = { 192, 105, false };

int alice_secret;
Point alice_shared;
Point alice_pub;


//------------------------------END of variable init----------------------------------

// Function to scroll text
// The function acepts the following arguments:
// row: row number where the text will be displayed
// message: message to scroll
// delayTime: delay between each character shifting
// lcdColumns: number of columns of your LCD
void scrollText(int row, String message, int delayTime, int lcdColumns) 
{
  for (int i=0; i < lcdColumns; i++) 
  {
    message = " " + message;  
  }
   
  message = message + " "; 
  
  for (int pos = 0; pos < message.length(); pos++) 
  {
    lcd.setCursor(0, row);
    lcd.print(message.substring(pos, pos + lcdColumns));
    delay(delayTime);
  }
}

// Function to show "unsigned char" text
// The function acepts the following arguments:
// msg: pointer to the message to be displayed.
// standard: boolean that states the operation mode of the function
// true -> We do not know how many chars are in the msg and we want to print everything
// false -> print the first 16 chars
void showMessage1(unsigned char* msg, bool standard)
{
    unsigned char i = 0;

    if (!standard)
    {
        for (i = 0; i < 16; i++)
        {
            Serial.print(" ");
            Serial.print(msg[i], HEX);
        }
    }
    else
        while (msg[i] != NULL && msg[i] != '\0' && msg[i] != 204)
        {
            Serial.print(" ");
            Serial.print(msg[i], HEX);
            i++;
        }
    Serial.println();
}

// Function to copy 8 bytes of "unsigned char" text
// The function acepts the following arguments:
// destination: pointer to the destination string.
// source: pointer to the source string.
// start: the value of the element in the string that we are starting to copy
inline void copyByteString(unsigned char* destination, unsigned char* source, unsigned char start)
{
  unsigned char i = 0;
  
  for(i = start; i < 8 + start; i++)
    destination[i] = source[i - start];
}

// Function to reinitialize the whole state machine
void PreProcessingPhase()
{
    changetoSlave = false;
    isSEEDrequestFulfilled = false;
    isAliceSent = false;

    burst = 0;
    encryptedFrame = 0;

    for(char i = 0; i < 17; i++)
        encryptedMessage[i] = '\0';

    failsafe = 0;
    iteration = 0;
}

// Controller ProcessingPhase
// Encrypt and send messages to the slave
void ProcessingPhase()
{

  Serial.println("In ProcessingPhase");

  byte data[8];

  long int t1;
  long int t2;
  
  t1 = millis();
  
  unsigned char plainText[9] = "";
  
  copyByteString(plainText, _LOCKDOOR, 0);
  
  unsigned char temp[17];
    
  unsigned char tempEncryptedMessage[17] = "\0";
    
  unsigned char temp1[16] = "";
    
  unsigned char* cipherText;
    
  bad_hash(initialKey, alice_shared.x); // "hash" the initial key

  Serial.print("Hashed key = ");
  showMessage1(initialKey, false);
  
  copynString(temp, plainText, 16, 0);
  Serial.print("temp = ");
  showMessage1(temp, true);
    
  checkPadding(temp, 1);
  Serial.print("Padded message = ");
  showMessage1(temp, true);
  
  cipherText = AES_encrypt_128(initialKey, temp);
  
  copyString(temp1, cipherText);
  Serial.print("Encrypted message = ");
  showMessage1(temp1, true);
    
  appendString(tempEncryptedMessage, temp1);
    
  t2 = millis();
  
  Serial.print("The execution time for the encryption algorithm is: ");
  Serial.print(t2 - t1);
  Serial.print("ms");
  Serial.println("");
  
  
  Serial.println("Sending Encrypted Frame...");
  Serial.print("Encrypted Message = ");
  showMessage1(tempEncryptedMessage, false);

  messageStatic = "Encryption CAN frame: ";

  lcd.setCursor(0, 0);
  lcd.print(messageStatic); // print data on the LCD screen
  
  scrollText(1, tempEncryptedMessage, 10, 16);
    
  // send 2 extended packets: id is 29 bits, each packet will contain 8 bytes of data

  copyByteString(data, tempEncryptedMessage, 0);
  Serial.print("First payload = ");
  showMessage1(data, true);

  writeCAN(encryptedFrame, data, 8);
  Serial.println("First payload sent....");
  
  delay(3000);

  copyByteString(data, tempEncryptedMessage, 8);
  Serial.print("Second payload = ");
  showMessage1(data, true);

  writeCAN(encryptedFrame, data, 8);
  Serial.println("Second payload sent....");
  
  delay(3000);

    if(iteration == 10)
    {
      iteration = 0;
      changetoSlave = true;
    }
    else
    {
      // do nothing  
    }
    
}

// Function to check if the SEED request was sent
// The function acepts the following arguments:
// msg: pointer to the message to be processed.
bool checkMessage(unsigned char* msg, unsigned char* text)
{
  unsigned char i = 0;
  
  for(i = 0; i < 8; i++)
    if(text[i] != msg[i])
      return false;

  return true;
}

// Controller PostProcessingPhase
// After 5 whole messages ( 10 payloads ) sent
// the controller will send a heartbeat request
// the processing of the heartbeat will be done
// this function.
void PostProcessingPhase()
{
  bad_hash(initialKey, alice_shared.x); // "hash" the initial key

  long int t1;
  long int t2;
  
  t1 = millis();
  unsigned char* decryptedMessge;
  unsigned char tempDecryptedMessage[9] = "\0";

  decryptedMessge = AES_128_decrypt(encryptedMessage);
  
  appendString(tempDecryptedMessage, decryptedMessge);
  
  removePadding(tempDecryptedMessage);  // in order to properly see the message we need to remove
                                       // the added padding
  t2 = millis();

  Serial.print("The execution time for the decryption algorithm is: ");
  Serial.print(t2 - t1);
  Serial.print("ms");
  Serial.println("");
  
  Serial.print("Decrypted message = ");
  showMessage1(tempDecryptedMessage, true);

  scrollText(1, tempDecryptedMessage, 10, 16);

  if(checkMessage(tempDecryptedMessage, _HEARTBEAT))
  {
    scrollText(1, " ", 10, 16);
    scrollText(1, "Heartbeat Recevied", 10, 16);
  }
  else if(checkMessage(tempDecryptedMessage, _OPENDOOR))
  {
    lcd.setCursor(0, 0);
    lcd.print("Door Unlocked"); // print data on the LCD screen
    lcd.setCursor(1, 0);
    lcd.print("Trusted Message");
  }
  else
  {
    lcd.setCursor(0, 0);
    lcd.print("Door Locked"); // print data on the LCD screen
    scrollText(1, "Non-Trusted Message", 10, 16);
  }

  PreProcessingPhase(); // reset the seed and the entire operation
}

// Function to lock the entire network in case of an attack
void lockDownProcedure()
{
  PreProcessingPhase();

  isNetworkInLockDown = true;

  writeCAN(encryptedFrame, _LOCKDOWN, 8);
  
  Serial.println("Network lock-down initiated!");
  Serial.println("Please insert the master key to deactivate the lock-down protocol.");
}

// Function that tells the slave to change it's seed
void changeSeedRequest()
{
  randomSeed(analogRead(0));

  encryptedFrame = random(0x80000000, 0x1FFFFFFF);// 1FFFFFFF - higher boundry 29-bits all = 1
                                                  // 0x80000000 - lower boundry - 29-bits the first one = 1
  Serial.print("The encrypted frame value for this session = ");
  Serial.println(encryptedFrame, HEX);
  
  alice_secret = random(1, 200);
  alice_pub = scalar_mult(alice_secret, G); // generate the public "keys" for alice and bob


  writeCAN(encryptedFrame, _CHANGE_SEED, 8);

  Serial.println("Sent the SEED change request");

  isSEEDrequestFulfilled = false;
  
}

// Function that runs in the booting phase
// start the Serial monitor and the CAN interface
void setup() 
{
  Serial.begin(115200);

  delay(3000);
  
  // Initialize MCP2515 running at 16MHz with a baudrate of 500kb/s and the masks and filters disabled.
  if(CAN0.begin(MCP_ANY, CAN_500KBPS, MCP_16MHZ) == CAN_OK)
    Serial.println("MCP2515 Initialized Successfully!");
  else
    Serial.println("Error Initializing MCP2515...");
  
  CAN0.setMode(MCP_NORMAL);                     // Set operation mode to normal so the MCP2515 sends acks to received data.

  pinMode(CAN0_INT, INPUT);
  
}

// Main state machine, will handle the network
void loop() 
{

  if(!isNetworkInLockDown)
  {

    if(!isSEEDrequestFulfilled)
    {
      changeSeedRequest();
      
      delay(2000);
      failsafe++;
      
      readCAN(); // We will continue to send SEED requests until we get an answer.
    }            
    else if(!isAliceSent)
    {
      delay(2000);
      
      readCAN();
      failsafe++;
    }
    else if(!changetoSlave)
    {
      iteration++;
      
      ProcessingPhase();
      delay(2000);
    }
    else if(changetoSlave)  // Check if the ECU is still active
    {
      if(burst != 2)
      {
        delay(2000);
        
        readCAN();  // if we did not receive 2 messages back to back we will read from CAN
        failsafe++;  // and update the failsafe so there are no problems
      }
      else if(burst == 2)
      { 
        PostProcessingPhase(); // start the ProcessingPhase, should be sending encrypted messages.
    
        burst = 0;    // reset the frame counter to prepare for the next message
        failsafe = 0;
      }
    }
    else
    {
      // do nothing  
    }
  
    
    if(failsafe > 10) // always check the failsafe to make sure everything is running smoothly
    {
      PreProcessingPhase(); // if there was a problem on the CAN reboot the system
      
      networkLockDown++;
      failsafe = 0;
    }
    else if(networkLockDown > 10)
    {
      lockDownProcedure(); // if we suspect that an attack is happening then we will lock-down the network
    }
    else
    {
      // do nothing
    }

  }
  else
  {
    messageStatic = "Network Locked";
    messageToScroll = "Please insert the master key to deactivate the lock-down protocol.";
    
    Serial.println("Network lock-down initiated!");
    Serial.println("Please insert the master key to deactivate the lock-down protocol.");
    
    lcd.setCursor(0, 0);
    lcd.print(messageStatic); // print data on the LCD screen
  
    scrollText(1, messageToScroll, 10, 16);  
  }
}

// Function to send a CAN message
// The function accepts the following arguments:
// id: the id of the CAN frame, can be 11 or 29 bit long, not in between
// data: the sent payload
// leng: payload length
void writeCAN(long id, unsigned char* data, unsigned char leng)
{
  // send data:  ID = encrypted frame, Data length = 8 bytes, 'data' = array of data bytes to send
  byte sndStat = CAN0.sendMsgBuf(id, leng, data);
  
  if(sndStat == CAN_OK)
  {
    Serial.println("Message Sent Successfully!");
  } 
  else 
  {
    Serial.println("Error Sending Message...");
  }
  delay(100);   // send data per 100ms
  
}

// Function to read a CAN message
// the function also handles the processing of the frame
void readCAN()
{
  if(!digitalRead(CAN0_INT))                         // If CAN0_INT pin is low, read receive buffer
  { 
    CAN0.readMsgBuf(&rxId, &len, rxBuf);      // Read data: len = data length, buf = data byte(s)

    if((rxId & encryptedFrame) == encryptedFrame) // filter any frame that comes
    {
      burst++;
      
      if((rxId & 0x80000000) == 0x80000000)     // Determine if ID is standard (11 bits) or extended (29 bits)
       {
        sprintf(msgString, "Extended ID: 0x%.8lX  DLC: %1d  Data:", (rxId & 0x1FFFFFFF), len);
        Serial.println(msgString);
       }
      else
      {
        sprintf(msgString, "Standard ID: 0x%.3lX       DLC: %1d  Data:", rxId, len);
        Serial.println(msgString);
      }
    
      if((rxId & 0x40000000) == 0x40000000)
      {    // Determine if message is a remote request frame.
        sprintf(msgString, " REMOTE REQUEST FRAME");
        Serial.println(msgString);
      } 
      else 
      {
        for(byte i = 0; i < len; i++)
        {
          sprintf(msgString, " 0x%.2X", rxBuf[i]);
          Serial.print(msgString);
        }
      }

      ProcessCANInput(len, rxBuf);
      
      Serial.println();
    }
    else
    {
      // do nothing
    }
  }
  else
  {
      // do nothing  
  }
  
}

// Function to process a CAN frame
// The function accepts the following arguments:
// packetSize: the size of the current payload
// message: the current payload
void ProcessCANInput(int packetSize, unsigned char* message)
{
  if((packetSize == 8 && burst != 0) && (isAliceSent && isSEEDrequestFulfilled))
  {
      switch(burst)
      {
        case 1:
            copyByteString(encryptedMessage, message, 0);
            showMessage1(encryptedMessage, true);
            
            failsafe = 0;
            break;
  
        case 2:
             failsafe = 0;
             
             copyByteString(encryptedMessage, message, 8);
             showMessage1(encryptedMessage, true);
             break;
             
        default:
              Serial.println("How did u get in here? Check burst conditions ASAP!!!");
              break;
        
       }
  }
  else if(packetSize == 8 && !isSEEDrequestFulfilled)
  {
    Point bob_pub;
    
    Serial.println("Recevied Bob, calculating...");

    bob_pub.x = (int)message[3];
    bob_pub.y = (int)message[7];
    
    alice_shared = scalar_mult(alice_secret, bob_pub);

    Serial.print("Bob.x = ");
    Serial.println(bob_pub.x);
    Serial.print("Bob.y = ");
    Serial.println(bob_pub.y);

    Serial.println("Alice_shared calculated");
    
    Serial.print("Alice_shared.x = ");
    Serial.println(alice_shared.x);
    Serial.print("Alice_shared.y = ");
    Serial.println(alice_shared.y);
    
    burst = 0;
    failsafe = 0;

    isSEEDrequestFulfilled = true;
  }
  else if(packetSize == 8 && !isAliceSent && isSEEDrequestFulfilled)
  {
    byte alice[8];
    
    alice[0] = (alice_pub.x >> 24) & 0xFF;
    alice[1] = (alice_pub.x >> 16) & 0xFF;
    alice[2] = (alice_pub.x  >> 8)  & 0xFF;
    alice[3] = alice_pub.x & 0xFF;
  
    alice[4] = (alice_pub.y >> 24) & 0xFF;
    alice[5] = (alice_pub.y >> 16) & 0xFF;
    alice[6] = (alice_pub.y  >> 8)  & 0xFF;
    alice[7] = alice_pub.y & 0xFF;

    writeCAN(encryptedFrame, alice, 8);
      
    Serial.println("Sending Alice");
    Serial.print("Alice X = ");
    Serial.println(alice_pub.x);
    Serial.print("Alice Y = ");
    Serial.println(alice_pub.y);

    isAliceSent = true;
    burst = 0;
    failsafe = 0;
    
  }
  else
  {
    // better performance, no statement stands in the air.
  }
}
