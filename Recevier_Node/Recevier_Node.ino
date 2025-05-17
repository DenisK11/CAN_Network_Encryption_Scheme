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
#define _CHANGE_SEED "chanSEED"
#define _LOCKDOWN "LOCKDOWN"
#define _OPENDOOR "OPENDOOR"
#define _HEARTBEAT "HEARTBEA"
#define _LOCKDOOR "LOCKDOOR"

// CAN network interface variables
MCP_CAN CAN0(AVR_UNO_CS);
long unsigned int rxId;
unsigned char len = 0;
unsigned char rxBuf[8];

// state machine variables
static bool changetoSlave = true;
static bool isAliceRecevied = false;
static bool isBobSent = false;
static bool isNetworkInLockDown = false;

static unsigned char burst = 0;
unsigned char networkLockDown = 0;  
unsigned char iteration = 0;
unsigned char failsafe = 0;

// Encryption algorithm variables
unsigned char initialKey[17] = "Initial Keysssss";
long unsigned int encryptedFrame = 0;
unsigned char encryptedMessage[17];

// ECDH variables with sugestive names for better tracking
Point G = { 192, 105, false };

int bob_secret;
Point bob_pub;
Point bob_shared;


//------------------------------END of variable init----------------------------------

void changeSeedRequest()
{
  byte bob[8];
  
  randomSeed(analogRead(0));
  
  bob_secret = random(1, 200);
  bob_pub = scalar_mult(bob_secret, G); // generate the public "keys" for alice and bob

  bob_pub.x = abs(bob_pub.x);
  bob_pub.y = abs(bob_pub.y);

  Serial.println(F("Bob = "));
  Serial.print(bob_pub.x);
  Serial.print(F(" "));
  Serial.println(bob_pub.y);


  bob[0] = (bob_pub.x >> 24) & 0xFF;
  bob[1] = (bob_pub.x >> 16) & 0xFF;
  bob[2] = (bob_pub.x  >> 8  )  & 0xFF;
  bob[3] = bob_pub.x & 0xFF;

  bob[4] = (bob_pub.y >> 24) & 0xFF;
  bob[5] = (bob_pub.y >> 16) & 0xFF;
  bob[6] = (bob_pub.y  >> 8  )  & 0xFF;
  bob[7] = bob_pub.y & 0xFF;

  Serial.println(F("Payload Sent on CAN"));
  
  for(int i = 0; i < 8; i++)
  {
    Serial.print(F("0x"));
    Serial.print(bob[i], HEX);
    Serial.print(F(" "));
  }
  
  writeCAN(encryptedFrame, bob, 8);

  isBobSent = true;
}

// Function to overwrite 8 bytes of "unsigned char" text
// The function acepts the following arguments:
// destination: pointer to the destination string.
// source: pointer to the source string.
// start: the value of the element in the string that we are starting to copy
inline void overwriteByteString(unsigned char* destination, unsigned char* source, unsigned char start)
{
  unsigned char i = 0;
  
  for(i = start; i < 8 + start; i++)
    destination[i - start] = source[i];
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
bool checkMessage(unsigned char* msg, unsigned char* text)
{
  unsigned char i = 0;
  
  for(i = 0; i < 8; i++)
    if(text[i] != msg[i])
      return false;

  return true;
}

// Function to reinitialize the whole state machine
void PreProcessingPhase()
{
    changetoSlave = true;
    isAliceRecevied = false;
    isBobSent = false;

    burst = 0;
    encryptedFrame = 0;

    for(char i = 0; i < 17; i++)
      encryptedMessage[i] = '\0';
      
    failsafe = 0;
    iteration = 0;
}

// Slave ProcessingPhase
// After 5 whole messages ( 10 payloads ) sent
// the controller will send a heartbeat request
// the processing of the heartbeat will be done
// this function.
void ProcessingPhase()
{
  bad_hash(initialKey, bob_shared.x); // "hash" the initial key

  generateKeys(initialKey);
  
  Serial.print(F("Key after hash = "));
  showMessage1(initialKey, false);

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

  Serial.print(F("The execution time for the decryption algorithm is: "));
  Serial.print(t2 - t1);
  Serial.print(F("ms"));
  Serial.println(F(""));
  
  Serial.print(F("Decrypted message = "));
  showMessage1(tempDecryptedMessage, true);

  if(checkMessage(tempDecryptedMessage, _LOCKDOOR))
  {
    Serial.println(F("Door locked"));
  }
  else if(checkMessage(tempDecryptedMessage, _LOCKDOWN))
  { 
    isNetworkInLockDown = true;
    failsafe = 0;
  }
  else if(checkMessage(tempDecryptedMessage, _OPENDOOR))
  {
    Serial.println(F("Door Open"));
    writeCAN(encryptedFrame, _OPENDOOR, 8);
  }

  if(iteration == 10)
  {
    iteration = 0;
    changetoSlave = false;  
  }
  else
  {
    // do nothing but save on time  
  }
  
}

// Slave PostProcessingPhase
// Encrypt and send messages to the slave
void PostProcessingPhase()
{

  Serial.println(F("In PostProcessingPhase"));

  byte data[8];

  unsigned long int t1;
  unsigned long int t2;
  
  unsigned char plainText[9] = "";

  overwriteByteString(plainText, _HEARTBEAT, 0);
  
  unsigned char temp[17];
    
  unsigned char temp1[17] = "";
    
  unsigned char* cipherText;

  // bad_hash(initialKey, bob_shared.x); // "hash" the initial key

  Serial.println(F("Hashed key = "));
  showMessage1(initialKey, false);
  
  copynString(temp, plainText, 16, 0);
  Serial.print(F("temp = "));
  showMessage1(temp, true);
    
  checkPadding(temp, 1);
  Serial.print(F("Padded message = "));
  showMessage1(temp, true);
  
  t1 = millis();
  
  cipherText = AES_encrypt_128(initialKey, temp);
  
  copyString(temp1, cipherText);
  Serial.print(F("Encrypted message = "));
  showMessage1(temp1, true);

  t2 = millis();
  
  Serial.print(F("The execution time for the encryption algorithm is: "));
  Serial.print(t2 - t1);
  Serial.print(F("ms"));
  Serial.println(F(""));
  
  
  Serial.println(F("Sending Encrypted Frame..."));
  
  // send 2 extended packets: id is 29 bits, each packet will contain 8 bytes of data

  overwriteByteString(data, temp1, 0);
  Serial.print(F("First payload = "));
  showMessage1(data, true);

  writeCAN(encryptedFrame, data, 8);
  Serial.println(F("First payload sent...."));
  
  delay(2000);

  overwriteByteString(data, temp1, 8);
  Serial.print(F("Second payload = "));
  showMessage1(data, true);

  writeCAN(encryptedFrame, data, 8);
  Serial.println(F("Second payload sent...."));
  
  delay(2000);

  PreProcessingPhase();
    
}

// Function to lock the entire network in case of an attack
void lockDownProcedure()
{
  PreProcessingPhase();

  isNetworkInLockDown = true;

  writeCAN(encryptedFrame, _LOCKDOWN, 8);
  
  Serial.println(F("Network lock-down initiated!"));
  Serial.println(F("Please insert the master key to deactivate the lock-down protocol."));
}

// Function that runs in the booting phase
// start the Serial monitor and the CAN interface
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
}

// Main state machine, will handle the network
void loop() 
{
  if(!isNetworkInLockDown)
  {
    
    if(!isBobSent)
    { 
      delay(1000);
      
      readCAN();
      
      failsafe++;
    }
    else if(changetoSlave)
    {
      if(burst != 2)
      {
        Serial.print(F("burst = "));
        Serial.println(burst);
        delay(3500);
        
        readCAN();  // if we did not receive 2 messages back to back we will read from CAN
        failsafe++;  // and update the failsafe so there are no problems
      }
      else if(burst == 2)
      {
        burst = 0;
        ProcessingPhase();
        iteration++;

      }
      else
      {
        // do nothing  
      }
      
    }
    else if(!changetoSlave)
    {
      PostProcessingPhase(); // start the ProcessingPhase, should be sending encrypted messages.
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
    Serial.println(F("Network lock-down initiated!"));
    Serial.println(F("Please insert the master key to deactivate the lock-down protocol."));
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
    Serial.println(F("Message Sent Successfully!"));
  } 
  else 
  {
    Serial.println(F("Error Sending Message..."));
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
        Serial.print(F("Extended ID: 0x"));
        Serial.print((rxId & 0x1FFFFFFF), HEX);
        Serial.print(F("  DLC: "));
        Serial.print(len);
        Serial.print(F("  Data:"));
       }
      else
      {
        Serial.println(F("Extended ID: 0x"));
        Serial.print(rxId);
        Serial.print(F("  DLC: "));
        Serial.print(len);
        Serial.print(F("  Data:"));
      }
    
      if((rxId & 0x40000000) == 0x40000000)
      {    // Determine if message is a remote request frame.
        Serial.println(F(" REMOTE REQUEST FRAME"));
      } 
      else 
      {
        for(byte i = 0; i < len; i++)
        {
          Serial.print(rxBuf[i], HEX);
          Serial.print(F(" "));
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

  Serial.print(F("Message = "));
  showMessage1(message, false);
  
  
  if((packetSize == 8 && burst != 0) && (isBobSent && isAliceRecevied))
  {
      switch(burst)
      {
        case 1:
            Serial.println(F("In burst = 1"));
            copyByteString(encryptedMessage, message, 0);
            showMessage1(encryptedMessage, true);

            failsafe = 0;
            break;
  
        case 2:
             failsafe = 0;

             Serial.println(F("In burst = 2"));
             copyByteString(encryptedMessage, message, 8);
             showMessage1(encryptedMessage, true);
             break;
             
        default:
              Serial.println(F("How did u get in here? Check burst conditions ASAP!!!"));
              break;
        
       }
  }
  else if(checkMessage(message, _CHANGE_SEED))
  {
    encryptedFrame = id;
    changeSeedRequest();
    
    Serial.println(F("SEED changed"));

    burst = 0;

  }
  else if((packetSize == 8 && isBobSent) && !isAliceRecevied)
  {
    Point alice_pub;
    
    Serial.println(F("Recevied Alice, calculating..."));

    alice_pub.x = (int)message[3];
    alice_pub.y = (int)message[7];
    
    bob_shared = scalar_mult(bob_secret, alice_pub);

    Serial.print(F("Bob secret = "));
    Serial.println(bob_secret);

    Serial.print(F("Alice.x = "));
    Serial.println(alice_pub.x);
    Serial.print(F("Alice.y = "));
    Serial.println(alice_pub.y);

    Serial.println(F("Bob_shared calculated"));
    
    Serial.print(F("Bob_shared.x = "));
    Serial.println(bob_shared.x);
    Serial.print(F("Bob_shared.y = "));
    Serial.println(bob_shared.y);
    
    burst = 0;
    failsafe = 0;

    isAliceRecevied = true;
  }
  else 
  {
    // better performance, no statement stands in the air.
  }
}
