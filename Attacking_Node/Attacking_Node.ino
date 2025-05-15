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

// CAN network interface variables
MCP_CAN CAN0(AVR_UNO_CS);
long unsigned int rxId;
unsigned char len = 0;
unsigned char rxBuf[8];

long unsigned int encryptedFrame = 0;

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
void copyByteString(unsigned char* destination, unsigned char* source, unsigned char start)
{
  unsigned char i = 0;
  
  for(i = start; i < 8 + start; i++)
    destination[i] = source[i - start];
}

void setup() 
{
    Serial.begin(115200);
  
  // Initialize MCP2515 running at 16MHz with a baudrate of 500kb/s and the masks and filters disabled.
  if(CAN0.begin(MCP_ANY, CAN_500KBPS, MCP_16MHZ) == CAN_OK)
    Serial.println("MCP2515 Initialized Successfully!");
  else
    Serial.println("Error Initializing MCP2515...");
  
  CAN0.setMode(MCP_NORMAL);                     // Set operation mode to normal so the MCP2515 sends acks to received data.

  pinMode(CAN0_INT, INPUT);  

}

void loop() {
  // put your main code here, to run repeatedly:

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
//      burst++;
      
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
//  if((packetSize == 8 && burst != 0) && (isBobSent && isAliceRecevied))
//  {
//      switch(burst)
//      {
//        case 1:
//            copyByteString(encryptedMessage, message, 0);
//            showMessage1(encryptedMessage, true);
//
//            failsafe = 0;
//            break;
//  
//        case 2:
//             failsafe = 0;
//             burst = 0;
//             
//             copyByteString(encryptedMessage, message, 8);
//             showMessage1(encryptedMessage, true);
//             break;
//             
//        default:
//              Serial.println("How did u get in here? Check burst conditions ASAP!!!");
//              break;
//        
//       }
//  }
//  else if(checkSEED(message))
//  {
//    encryptedFrame = id;
//    changeSeedRequest();
//    
//    Serial.println("SEED changed");
//
//    burst = 0;
//
//  }
//  else if((packetSize == 8 && isBobSent) && !isAliceRecevied)
//  {
//    Point alice_pub;
//    
//    Serial.println("Recevied Alice, calculating...");
//
//    alice_pub.x = (int)message[3];
//    alice_pub.y = (int)message[7];
//    
//    bob_shared = scalar_mult(bob_secret, alice_pub);
//
//    Serial.print("Alice.x = ");
//    Serial.println(alice_pub.x);
//    Serial.print("Alice.y = ");
//    Serial.println(alice_pub.y);
//
//    Serial.println("Bob_shared calculated");
//    
//    Serial.print("Bob_shared.x = ");
//    Serial.println(bob_shared.x);
//    Serial.print("Bob_shared.y = ");
//    Serial.println(bob_shared.y);
//    
//    burst = 0;
//    failsafe = 0;
//
//    isAliceRecevied = true;
//  }
//  else 
//  {
//    // better performance, no statement stands in the air.
//  }
}
