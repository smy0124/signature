package com.ht1008.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.TextField;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class ItextUtil {

    public static final char[] PASSWORD = "123456".toCharArray();//keystory密码

    /**
     * 单多次签章通用
     * @param src
     * @param target
     * @param signatureInfos
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws DocumentException
     */
    public void sign(String src, String target, SignatureInfo... signatureInfos){
        InputStream inputStream = null;
        FileOutputStream outputStream = null;
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try {
            inputStream = new FileInputStream(src);
            for (SignatureInfo signatureInfo : signatureInfos) {
                ByteArrayOutputStream tempArrayOutputStream = new ByteArrayOutputStream();
                PdfReader reader = new PdfReader(inputStream);
                //创建签章工具PdfStamper ，最后一个boolean参数是否允许被追加签名
                PdfStamper stamper = PdfStamper.createSignature(reader, tempArrayOutputStream, '\0', null, true);
                // 获取数字签章属性对象
                PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
                appearance.setReason(signatureInfo.getReason());
                appearance.setLocation(signatureInfo.getLocation());
                //设置签名的签名域名称，多次追加签名的时候，签名预名称不能一样，图片大小受表单域大小影响（过小导致压缩）
                appearance.setVisibleSignature(new Rectangle(500, 10, 550, 50), 2, signatureInfo.getFieldName());
                //读取图章图片
                Image image = Image.getInstance(signatureInfo.getImagePath());
                appearance.setSignatureGraphic(image);
                appearance.setCertificationLevel(signatureInfo.getCertificationLevel());
                //设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
                appearance.setRenderingMode(signatureInfo.getRenderingMode());
                // 摘要算法
                ExternalDigest digest = new BouncyCastleDigest();
                // 签名算法
                ExternalSignature signature = new PrivateKeySignature(signatureInfo.getPk(), signatureInfo.getDigestAlgorithm(), null);
                // 调用itext签名方法完成pdf签章
                MakeSignature.signDetached(appearance, digest, signature, signatureInfo.getChain(), null, null, null, 0, signatureInfo.getSubfilter());
                //定义输入流为生成的输出流内容，以完成多次签章的过程
                inputStream = new ByteArrayInputStream(tempArrayOutputStream.toByteArray());
                result = tempArrayOutputStream;
            }
            outputStream = new FileOutputStream(new File(target));
            outputStream.write(result.toByteArray());
            outputStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if(null!=outputStream){
                    outputStream.close();
                }
                if(null!=inputStream){
                    inputStream.close();
                }
                if(null!=result){
                    result.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    
    /**
     * 单多次签章通用
     * @param src
     * @param target
     * @param signatureInfos
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws DocumentException
     */
    public static ByteArrayOutputStream signature(String srcFile, String imagePath,String p12Path){
        InputStream inputStream = null;
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try {
        	
             //将证书文件放入指定路径，并读取keystore ，获得私钥和证书链
             //String pkPath = app.getClass().getResource("D:\\client1.p12").getPath();
             KeyStore ks = KeyStore.getInstance("PKCS12");
             ks.load(new FileInputStream(p12Path), PASSWORD);
             String alias = ks.aliases().nextElement();
             PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
             Certificate[] chain = ks.getCertificateChain(alias);
             
             
            inputStream = new FileInputStream(srcFile);
            PdfReader reader = new PdfReader(inputStream);
            //创建签章工具PdfStamper ，最后一个boolean参数是否允许被追加签名
            PdfStamper stamper = PdfStamper.createSignature(reader, result, '\0', null, true);
            // 获取数字签章属性对象
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason("");
            appearance.setLocation("");
            //设置签名的签名域名称，多次追加签名的时候，签名预名称不能一样，图片大小受表单域大小影响（过小导致压缩）
            appearance.setVisibleSignature(new Rectangle(500, 10, 550, 50), 2, "sig1");
            //读取图章图片
            Image image = Image.getInstance(imagePath);
            appearance.setSignatureGraphic(image);
            appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
            //设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            // 摘要算法
            ExternalDigest digest = new BouncyCastleDigest();
            // 签名算法
            ExternalSignature signature = new PrivateKeySignature(pk, DigestAlgorithms.SHA1, null);
            // 调用itext签名方法完成pdf签章
            MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, null);
            //定义输入流为生成的输出流内容，以完成多次签章的过程
            inputStream = new ByteArrayInputStream(result.toByteArray());
            return result;
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if(null!=inputStream){
                    inputStream.close();
                }
                if(null!=result){
                    result.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
		return result;
    }
    
    /**
     * pdf设置域的值     操作pdf可以用迅捷pdf编辑器
     * @param templateFile
     * @param outFile
     * @throws IOException
     * @throws DocumentException
     */
    public static void editPdfTemplate(String templateFile, String outFile)
    		throws IOException, DocumentException {
    		PdfReader reader = new PdfReader(templateFile); // 模版文件目录
    		PdfStamper ps = new PdfStamper(reader, new FileOutputStream(outFile)); // 生成的输出流
    		BaseFont bf = BaseFont.createFont("STSong-Light","UniGB-UCS2-H",BaseFont.NOT_EMBEDDED);
    		AcroFields s =  ps.getAcroFields();
    		//设置文本域表单的字体
    		// 对于模板要显中文的，在此处设置字体比在pdf模板中设置表单字体的好处：
    		//1.模板文件的大小不变；2.字体格式满足中文要求
    		s.setFieldProperty("Text1","textfont",bf,null);
    		s.setFieldProperty("Text2","textfont",bf,null);
    		s.setFieldProperty("Text3","textfont",bf,null);
    		s.setFieldProperty("Text4","textfont",bf,null);
    		//编辑文本域表单的内容
    		s.setField("Text1", "姚 秀 才");
    		s.setField("Text2", "cf");
    		s.setField("Text3", "cn-990000");
    		s.setField("Text4",  "模版文件目录");
    		//s.setFieldProperty("Text1","readonly",TextField.READ_ONLY,null);
    		ps.setFormFlattening(true); // 这句不能少
    		ps.close();
    		reader.close();
    }
///////////////////////////////////////////// PDF签章    
    public static void main(String[] args) {
    	FileOutputStream outputStream = null;
    	try {
	    	File directory = new File("");// 
	        String courseFile = directory.getCanonicalPath() + "\\src\\main\\resources\\";
	        
	    	ByteArrayOutputStream result = signature(courseFile+"11.pdf",courseFile+"timg.jpg",courseFile+"me.p12");
	    	
			outputStream = new FileOutputStream(new File(courseFile+"sign4.pdf"));
			outputStream.write(result.toByteArray());
			outputStream.flush();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if(outputStream != null){
					outputStream.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
    }
    
    
	/*
	 * public static void main(String[] args) {
	 * 
	 * try { File directory = new File("");// String courseFile =
	 * directory.getCanonicalPath() + "\\src\\main\\resources\\";
	 * editPdfTemplate(courseFile + "11.pdf", courseFile + "result_field.pdf"); }
	 * catch (Exception e) { } }
	 */
}
