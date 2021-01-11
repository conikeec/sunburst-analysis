import java.util._
import java.nio._
import java.nio.charset._
import java.util.zip.Inflater

def deflate(value: Array[Byte]): String = {
 try {
     // Compress the bytes
     val decompresser = new Inflater(true)
     decompresser.setInput(value)
     val result = new Array[Byte](value.length * 100)
     val resultLength = decompresser.inflate(result, 0, result.length)
     decompresser.end()

     new String(result, 0, resultLength, "UTF-8")
 } catch {
   case ex: java.io.UnsupportedEncodingException => ""
   case ex: java.util.zip.DataFormatException => ""
 }
}

def decodeBase64(): String = {
    cpg.literal
       .code("\"[a-zA-Z0-9/+]+={0,2}\"")
       .code
       .map(s => s.substring(1, s.length - 1))
       .filter(_.length >= 2)
       .map{ str =>
            deflate(Base64.getDecoder.decode(str.getBytes(Charset.forName("UTF-8"))))
           }
       .filter(_.nonEmpty)
       .l
       .sorted
       .distinct
       .mkString("\n")
}
