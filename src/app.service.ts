import { Injectable } from '@nestjs/common';
import { FileHandle, open, readFile, writeFile } from 'fs/promises';
import { subtle } from 'crypto';
import * as path from 'node:path';
import { Mode } from 'node:fs';

type TAESData = {
  key: string;
  iv: string;
};

@Injectable()
export class AppService {
  async saveAESKeyAndIVinFile(data: TAESData, forFile: string) {
    try {
      await writeFile(
        path.join(__dirname, '..', '/files/certs-' + forFile),
        JSON.stringify(data),
      );
    } catch (err) {
      console.error('Error file saving: ', err);
      throw err;
    }
  }
  async getPublicKey() {
    try {
      const publicKeyFile = await this.openFile(
        path.join(__dirname, '..', '/keys/pub.pem'),
      );
      const publicKeyContent = await this.parseKeyFile(
        publicKeyFile,
        '-----BEGIN PUBLIC KEY-----',
        '-----END PUBLIC KEY-----',
      );

      if (!publicKeyContent.length) {
        throw new Error('Empty file');
      }

      return publicKeyContent;
    } catch (err) {
      console.error('Error public key opening: ', err);
      throw err;
    }
  }

  async decryptFile(fileName: string) {
    try {
      const privateKeyFile = await this.openFile(
        path.join(__dirname, '..', '/keys/pkcs8.key'),
      );
      const decryptedFile = await this.decrypt(
        privateKeyFile,
        path.join(__dirname, '..', '/files', fileName),
        path.join(__dirname, '..', '/files/certs-' + fileName),
      );
      const newFile = await this.openFile(
        path.join(__dirname, '..', `/files/decrypted-${fileName}`),
        'w',
      );
      await newFile.writeFile(new Uint8Array(decryptedFile));
    } catch (err) {
      console.error('Error file decryption: ', err);
      throw err;
    }
  }

  async decryptText(msg: string, key: string, iv: string) {
    try {
      const privateKeyFile = await this.openFile(
        path.join(__dirname, '..', '/keys/pkcs8.key'),
      );

      const privateKeyContent = await this.parseKeyFile(
        privateKeyFile,
        '-----BEGIN PRIVATE KEY-----',
        '-----END PRIVATE KEY-----',
      );
      const encryptedKey = Buffer.from(key, 'base64');
      const decryptedKeyArrayBuffer = await this.decryptAESEncryptionKey(
        privateKeyContent,
        encryptedKey,
      );

      const decryptedMessage = await this.decryptWithAES_CBC(
        Buffer.from(msg, 'base64'),
        decryptedKeyArrayBuffer,
        iv,
      );

      return new TextDecoder().decode(decryptedMessage);
    } catch (err) {
      console.error('Error text decryption: ', err);
      throw err;
    }
  }

  private async decryptWithAES_CBC(
    data: ArrayBuffer,
    key: ArrayBuffer,
    iv: string,
  ) {
    try {
      const importedKey = await this.importAESKey(key);
      return await subtle.decrypt(
        {
          name: 'AES-CBC',
          iv: Buffer.from(iv, 'base64'),
        },
        importedKey,
        data,
      );
    } catch (err) {
      console.log('Error message decrypt with AES-CBC: ', err);
      throw err;
    }
  }

  private async importAESKey(key: ArrayBuffer) {
    try {
      return await subtle.importKey(
        'raw',
        key,
        {
          name: 'AES-CBC',
        },
        true,
        ['decrypt', 'encrypt'],
      );
    } catch (err) {
      console.log('Error key AES-CBC import: ', err);
      throw err;
    }
  }

  private async decryptAESEncryptionKey(
    privateKeyContent: string,
    encryptedKey: ArrayBuffer,
  ) {
    const decryptionKey = await this.importRSADecryptKey(privateKeyContent);

    return await subtle.decrypt(
      { name: 'RSA-OAEP' },
      decryptionKey,
      encryptedKey,
    );
  }

  private async decrypt(
    privateKeyFile: FileHandle,
    filePath: string,
    certFilePath: string,
  ) {
    try {
      const privateKeyContent = await this.parseKeyFile(
        privateKeyFile,
        '-----BEGIN PRIVATE KEY-----',
        '-----END PRIVATE KEY-----',
      );
      const certs = await this.openFile(certFilePath);
      const certDataBuffer = await certs.readFile();
      const certData = JSON.parse(certDataBuffer.toString()) as TAESData;
      const encryptedKey = Buffer.from(certData.key, 'base64');
      const srcBinary = await readFile(filePath);
      const decryptedKeyArrayBuffer = await this.decryptAESEncryptionKey(
        privateKeyContent,
        encryptedKey,
      );
      const importedKey = await this.importAESKey(decryptedKeyArrayBuffer);

      return await subtle.decrypt(
        {
          name: 'AES-CBC',
          iv: Buffer.from(certData.iv, 'base64'),
        },
        importedKey,
        srcBinary,
      );
    } catch (err) {
      console.error('Error data decryption: ', err);
      throw err;
    }
  }

  private async importRSADecryptKey(pemFileContent: string) {
    try {
      const binaryKey = this.stob(atob(pemFileContent));
      return await subtle.importKey(
        'pkcs8',
        binaryKey,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256',
        },
        false,
        ['decrypt'],
      );
    } catch (err) {
      console.log('Error key import: ', err);
      throw err;
    }
  }

  private async parseKeyFile(
    file: FileHandle,
    header?: string,
    footer?: string,
  ) {
    let result: string = '';
    for await (const line of file.readLines()) {
      if (!line.includes(header) && !line.includes(footer)) {
        result += line.trim();
      }
    }
    return result;
  }

  private async openFile(
    filePath: string,
    flag?: string | number,
    mode?: Mode,
  ) {
    try {
      return await open(filePath, flag, mode);
    } catch (err) {
      console.error('Error file opening: ', err);
      process.exit(0);
      throw err;
    }
  }

  private stob(s: string) {
    const buf = new ArrayBuffer(s.length);
    const bList = new Uint8Array(buf);
    for (let i = 0; i < s.length; i++) {
      bList[i] = s.charCodeAt(i);
    }
    return buf;
  }
}
