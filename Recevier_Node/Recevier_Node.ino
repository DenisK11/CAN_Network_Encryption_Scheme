// Imported Arduino libraries
#include <mcp_can.h>
#include <SPI.h>

// Homemade libraries
#include "AES_128.h"
#include "ECDH.h"
#include "Utilities.h"

// Helpful defines
#define _CHANGE_SEED "chanSEED"
#define CAN0_INT 2
#define AVR_UNO_CS 10
#define _LOCKDOWN "LOCKDOWN"

// CAN network interface variables
MCP_CAN CAN0(AVR_UNO_CS);
long unsigned int rxId;
unsigned char len = 0;
unsigned char rxBuf[8];
char msgString[128];                        // Array to store serial string

// state machine variables
static bool changetoSlave = true;
static bool isSEEDRequestReceived = false;
static bool isBobSent = false;
static bool isNetworkInLockDown = false;

static int burst = -1;
unsigned char networkLockDown = 0;  
unsigned char iteration = 0;
unsigned char failsafe = 0;

// Encryption algorithm variables
unsigned char initialKey[17] = "Initial Keysssss";
long encryptedFrame;
unsigned char encryptedMessage[17];

// ECDH variables with sugestive names for better tracking
Point G = { 192, 105, false };

int bob_secret;
Point bob_pub;
Point bob_shared;

Point alice_pub;

//------------------------------END of variable init----------------------------------

void changeSeedRequest()
{
  byte bob[8];
  
  randomSeed(analogRead(0));
  
  bob_secret = random(1, 200);
  bob_pub = scalar_mult(bob_secret, G); // generate the public "keys" for alice and bob

  bob_pub.x = abs(bob_pub.x);
  bob_pub.y = abs(bob_pub.y);

  Serial.println("Bob = ");
  Serial.print(bob_pub.x);
  Serial.print(" ");
  Serial.println(bob_pub.y);


  bob[0] = (bob_pub.x >> 24) & 0xFF;
  bob[1] = (bob_pub.x >> 16) & 0xFF;
  bob[2] = (bob_pub.x  >> 8  )  & 0xFF;
  bob[3] = bob_pub.x & 0xFF;

  bob[4] = (bob_pub.y >> 24) & 0xFF;
  bob[5] = (bob_pub.y >> 16) & 0xFF;
  bob[6] = (bob_pub.y  >> 8  )  & 0xFF;
  bob[7] = bob_pub.y & 0xFF;

  Serial.println("Payload Sent on CAN");
  
  for(int i = 0; i < 8; i++)
  {
    Serial.print(bob[i]);
    Serial.print(" ");
  }
  
  writeCAN(encryptedFrame, bob, 8);

  isBobSent = true;
  
  isSEEDRequestReceived = true;
}

// Function to copy 8 bytes of "unsigned char" text
// The function acepts the following arguments:
// destination: pointer to the destination string.
// source: pointer to the source string.
// start: the value of the element in the string that we are starting to copy
void copyByteString(unsigned char* destination, unsigned char* source, unsigned char start)
{
  unsigned char i = 0;
  
  for(i = start; i < 8 + start; i++)
    destination[i] = source[i - start];
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

// Function to check if the SEED request was sent
// The function acepts the following arguments:
// msg: pointer to the message to be processed.
bool checkSEED(unsigned char* msg)
{
  unsigned char i = 0;
  
  for(i = 0; i < 8; i++)
    if(_CHANGE_SEED[i] != msg[i])
      return false;

  return true;
}

// Function to reinitialize the whole state machine
void PreProcessingPhase()
{
    changetoSlave = false;
    isSEEDRequestReceived = false;
    isBobSent = false;

    burst = 0;
    encryptedFrame = 0;

    for(char i = 0; i < 17; i++)
      encryptedMessage[i] = '\0';
      
    failsafe = 0;
    iteration = 0;
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

// Function that runs in the booting phase
// start the Serial monitor and the CAN interface
void setup() {
  Serial.begin(115200);
  
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
  if(changetoSlave)
  {
    readCAN();
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

      ProcessCANInput(len, rxBuf, rxId);
      
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
// id: the current id of the frame
inline void ProcessCANInput(int packetSize, unsigned char* message, long id)
{
  if((packetSize == 8 && burst != 0) && (isBobSent && isSEEDRequestReceived))
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
             burst = 0;
             
             copyByteString(encryptedMessage, message, 8);
             showMessage1(encryptedMessage, true);
             break;
             
        default:
              Serial.println("How did u get in here? Check burst conditions ASAP!!!");
              break;
        
       }
  }
  else if(checkSEED(message))
  {
    encryptedFrame = id;
    changeSeedRequest();
    
    Serial.println("SEED changed");

    burst = 0;

  }
  else if(packetSize == 8 && isBobSent)
  {
    // writeCAN(encryptedFrame, alice_pub.x + alice_pub.y + F);
    
    burst = 0;
      
    Serial.println("Sending Alice");
    Serial.print("Alice X = ");
    Serial.println(alice_pub.x);
    Serial.print("Alice Y = ");
    Serial.println(alice_pub.y);
  }
  else if(packetSize == 3)
  {
    Serial.println("Recevied Alice, calculating...");

    alice_pub.x = message[0];
    alice_pub.y = message[1];
    bob_shared = scalar_mult(bob_secret, bob_pub);
    
    Serial.println("Bob_shared calculated");

    burst = 0;
  }
  else 
  {
    
  }
}
