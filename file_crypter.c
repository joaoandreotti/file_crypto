#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/types.h>
#include <sys/stat.h>

const uint8_t KEY_SIZE = 32;
const uint8_t BLOCK_SIZE = 16;
const uint32_t BUFFER_SIZE = 4096;

const uint8_t* password = "Password123#@!";
const uint32_t passwordSize = 14;
const uint8_t salt[8] = {1, 2, 3, 4, 5, 6, 7, 8};
const uint32_t rounds = 5;

uint8_t key[32];
uint8_t iv[32];
EVP_CIPHER_CTX* encryptContext;
EVP_CIPHER_CTX* decryptContext;

void initAES()
{
  // CREATING KEY AND IV
  EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(),
      salt, password, passwordSize, rounds, key, iv);

  // CREATING ENCRYPTION CONTEXT
  encryptContext = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_reset(encryptContext);
  EVP_EncryptInit_ex(encryptContext, EVP_aes_256_cbc(), NULL, key, iv);
  // CREATING DECRYPTION CONTEXT
  decryptContext = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_reset(decryptContext);
  EVP_DecryptInit_ex(decryptContext, EVP_aes_256_cbc(), NULL, key, iv);
}

uint8_t* encryptMessage(uint8_t* plainMessage, uint32_t plainMessageSize, uint32_t* cipherMessageSize)
{
  EVP_EncryptInit_ex(encryptContext, NULL, NULL, NULL, NULL);
  // CREATING ENCRYPTION VARIABLES
  *cipherMessageSize = BUFFER_SIZE + BLOCK_SIZE;
  uint8_t* cipherMessage = malloc(*cipherMessageSize);
  // ENCRYPTING THE MESSAGE
  EVP_EncryptUpdate(encryptContext,
      cipherMessage, cipherMessageSize, plainMessage, plainMessageSize);
  uint32_t paddingSize = 0;
  EVP_EncryptFinal_ex(encryptContext,
      cipherMessage + *cipherMessageSize, &paddingSize);
  *cipherMessageSize += paddingSize;
  return cipherMessage;
}

uint8_t* decryptMessage(uint8_t* cipherMessage, uint32_t cipherSize, uint32_t* decryptedMessageSize)
{
  EVP_DecryptInit_ex(decryptContext, NULL, NULL, NULL, NULL);
  // CREATING DECRYPTION VARIABLES
  *decryptedMessageSize = BUFFER_SIZE + BLOCK_SIZE;
  uint8_t* decryptedMessage = malloc(*decryptedMessageSize);
  // ENCRYPTING THE MESSAGE
  EVP_DecryptUpdate(decryptContext,
      decryptedMessage, decryptedMessageSize, cipherMessage, cipherSize);
  uint32_t paddingSize = 0;
  EVP_DecryptFinal_ex(decryptContext,
      decryptedMessage + *decryptedMessageSize, &paddingSize);
  *decryptedMessageSize += paddingSize;

  return decryptedMessage;
}

uint32_t getFileSize(FILE* filePointer)
{
  fseek(filePointer, 0, SEEK_END);
  uint32_t fileSize = ftell(filePointer);
  rewind(filePointer);
  return fileSize;
}

uint32_t readPlainFileBuffer(uint8_t* fileBuffer, uint32_t fileBufferSize, FILE* filePointer, uint32_t readPosition)
{
  uint32_t plainSize = 0;
  fseek(filePointer, readPosition, SEEK_SET);
  while((fileBufferSize - plainSize) && plainSize < (BUFFER_SIZE - BLOCK_SIZE - 1))
    fileBuffer[plainSize++] = getc(filePointer);
  fileBuffer[plainSize] = 0;
  return plainSize;
}

uint32_t readEncryptedFileBuffer(uint8_t* fileBuffer, uint32_t fileBufferSize, FILE* filePointer, uint32_t readPosition)
{
  uint32_t plainSize = 0;
  fseek(filePointer, readPosition, SEEK_SET);
  while((fileBufferSize - plainSize) > 0 && plainSize < (BUFFER_SIZE - BLOCK_SIZE))
    fileBuffer[plainSize++] = getc(filePointer);
  return plainSize;
}

void writeFileBuffer(uint8_t* fileBuffer, uint32_t fileBufferSize, FILE* filePointer, uint32_t writePosition)
{
  fseek(filePointer, writePosition, SEEK_SET);
  for(uint32_t i = 0; i < fileBufferSize; i++)
    fputc(fileBuffer[i], filePointer);
}

void encryptFile(uint8_t* fileName)
{
  initAES(password, passwordSize);
  FILE* fileToBeEncrypted = fopen(fileName, "rb+");
  uint32_t fileSize = getFileSize(fileToBeEncrypted);
  uint8_t plainTextBuffer[BUFFER_SIZE + BLOCK_SIZE];
  uint32_t writePosition = 0;
  uint32_t readPosition = 0;
  while(fileSize)
  {
    uint32_t plainTextBufferSize =
      readPlainFileBuffer(plainTextBuffer, fileSize, fileToBeEncrypted, readPosition);
    readPosition += plainTextBufferSize;
    fileSize -= plainTextBufferSize;
    uint32_t cipherSize;
    uint8_t* cipherText;
    cipherText = encryptMessage(plainTextBuffer, plainTextBufferSize, &cipherSize);
    writeFileBuffer(cipherText, cipherSize, fileToBeEncrypted, writePosition);
    writePosition += cipherSize;
    free(cipherText);
  }
  fclose(fileToBeEncrypted);
}

void decryptFile(uint8_t* fileName)
{
  initAES(password, passwordSize);
  FILE* fileToBeDecrypted = fopen(fileName, "rb+");
  uint32_t fileSize = getFileSize(fileToBeDecrypted);
  uint8_t encryptedBuffer[BUFFER_SIZE + BLOCK_SIZE];
  uint32_t writePosition = 0;
  uint32_t readPosition = 0;
  while(fileSize)
  {
    uint32_t encryptedBufferSize =
      readEncryptedFileBuffer(encryptedBuffer, fileSize, fileToBeDecrypted, readPosition);
    readPosition += encryptedBufferSize;
    fileSize -= encryptedBufferSize;
    uint32_t plainTextSize;
    uint8_t *plainText;
    plainText = decryptMessage(encryptedBuffer, encryptedBufferSize, &plainTextSize);
    writeFileBuffer(plainText, plainTextSize, fileToBeDecrypted, writePosition);
    writePosition += plainTextSize;
    free(plainText);
  }
  //_chsize(_fileno(fileToBeDecrypted), writePosition);
  ftruncate(fileno(fileToBeDecrypted), writePosition);
  fclose(fileToBeDecrypted);
}

int32_t main()
{
  puts("Encrypting...");
  encryptFile("plainText");
  puts("Finishing...");
  puts("Decrypting...");
  decryptFile("plainText");
  puts("Finishing...");
  return 0;
}
