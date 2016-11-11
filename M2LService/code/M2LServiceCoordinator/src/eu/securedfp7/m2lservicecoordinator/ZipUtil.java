package eu.securedfp7.m2lservicecoordinator;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
 
public class ZipUtil {
 
 public static byte[] MAGIC = { 'P', 'K', 0x3, 0x4 };
 
 /**
  * The method to test if a input stream is a zip archive.
  * 
  * @param in
  *            the input stream to test.
  * @return
  */
 public static boolean isZipStream(InputStream in) {
  if (!in.markSupported()) {
   in = new BufferedInputStream(in);
  }
  boolean isZip = true;
  try {
   in.mark(MAGIC.length);
   for (int i = 0; i < MAGIC.length; i++) {
    if (MAGIC[i] != (byte) in.read()) {
     isZip = false;
     break;
    }
   }
   in.reset();
  } catch (IOException e) {
   isZip = false;
  }
  return isZip;
 }
 
 /**
  * Test if a file is a zip file.
  * 
  * @param f
  *            the file to test.
  * @return
  */
 public static boolean isZipFile(File f) {
 
  boolean isZip = true;
  byte[] buffer = new byte[MAGIC.length];
  try {
   RandomAccessFile raf = new RandomAccessFile(f, "r");
   raf.readFully(buffer);
   for (int i = 0; i < MAGIC.length; i++) {
    if (buffer[i] != MAGIC[i]) {
     isZip = false;
     break;
    }
   }
   raf.close();
  } catch (Throwable e) {
   isZip = false;
  }
  return isZip;
 }
 
 public static void zipFile(File inputFile, String zipFilePath) {
     try {

         // Wrap a FileOutputStream around a ZipOutputStream
         // to store the zip stream to a file. Note that this is
         // not absolutely necessary
         FileOutputStream fileOutputStream = new FileOutputStream(zipFilePath);
         ZipOutputStream zipOutputStream = new ZipOutputStream(fileOutputStream);

         // a ZipEntry represents a file entry in the zip archive
         // We name the ZipEntry after the original file's name
         ZipEntry zipEntry = new ZipEntry(inputFile.getName());
         zipOutputStream.putNextEntry(zipEntry);

         FileInputStream fileInputStream = new FileInputStream(inputFile);
         byte[] buf = new byte[1024];
         int bytesRead;

         // Read the input file by chucks of 1024 bytes
         // and write the read bytes to the zip stream
         while ((bytesRead = fileInputStream.read(buf)) > 0) {
             zipOutputStream.write(buf, 0, bytesRead);
         }

         // close ZipEntry to store the stream to the file
         zipOutputStream.closeEntry();

         zipOutputStream.close();
         fileOutputStream.close();

         System.out.println("Regular file :" + inputFile.getCanonicalPath()+" is zipped to archive :"+zipFilePath);

     } catch (IOException e) {
         e.printStackTrace();
     }

 }
}