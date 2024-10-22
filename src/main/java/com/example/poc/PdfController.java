package com.example.poc;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;

import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import java.time.Duration;

@RestController
public class PdfController {

    private static final Logger logger = LoggerFactory.getLogger(PdfController.class);
    private final S3Client s3Client;
    private final S3Presigner s3Presigner;
    private final String bucketName;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public PdfController(S3Client s3Client, S3Presigner s3Presigner, String bucketName) {
        this.s3Client = s3Client;
        this.s3Presigner = s3Presigner;
        this.bucketName = bucketName;
    }

    @GetMapping("/generate-pdf")
    public ResponseEntity<byte[]> generatePdf() {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                contentStream.setFont(PDType1Font.HELVETICA_BOLD, 12);
                contentStream.beginText();
                contentStream.newLineAtOffset(100, 700);
                contentStream.showText("Hello, this is a sample PDF document!");
                contentStream.endText();
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            byte[] pdfBytes = baos.toByteArray();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("filename", "sample.pdf");

            return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
        } catch (IOException e) {
            logger.error("Error generating PDF", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/generate-signed-pdf")
    public ResponseEntity<String> generateSignedPdf() {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                contentStream.setFont(PDType1Font.HELVETICA_BOLD, 12);
                contentStream.beginText();
                contentStream.newLineAtOffset(100, 700);
                contentStream.showText("Hello, this is a signed PDF document!");
                contentStream.endText();
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            byte[] unsignedPdfBytes = baos.toByteArray();

            byte[] signedPdfBytes = signPdf(unsignedPdfBytes);

            String fileName = "signed_sample_" + System.currentTimeMillis() + ".pdf";
            String presignedUrl = uploadToS3AndGenerateUrl(signedPdfBytes, fileName);

            return new ResponseEntity<>(presignedUrl, HttpStatus.OK);
        } catch (Exception e) {
            logger.error("Error generating signed PDF", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private byte[] signPdf(byte[] pdfBytes) throws Exception {
        try (PDDocument document = PDDocument.load(pdfBytes)) {
            logger.info("Starting PDF signing process");
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Test User");
            signature.setLocation("City");
            signature.setReason("Testing");
            signature.setSignDate(Calendar.getInstance());
            logger.info("Signature object created");

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            char[] password = "testpassword".toCharArray();
            String keystorePath = "keystore.p12";

            logger.info("Checking keystore file existence");
            if (!Files.exists(Paths.get(keystorePath))) {
                logger.error("Keystore file not found: {}", keystorePath);
                throw new IOException("Keystore file not found: " + keystorePath);
            }
            logger.info("Keystore file found");

            logger.info("Loading keystore");
            try (InputStream is = new FileInputStream(keystorePath)) {
                keyStore.load(is, password);
            }
            logger.info("Keystore loaded successfully");

            String alias = "testkey";
            logger.info("Retrieving private key and certificate chain for alias: {}", alias);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
            Certificate[] certificateChain = keyStore.getCertificateChain(alias);

            if (privateKey == null || certificateChain == null) {
                logger.error("Private key or certificate chain not found in keystore");
                throw new Exception("Private key or certificate chain not found in keystore");
            }
            logger.info("Private key and certificate chain retrieved successfully");

            logger.info("Adding signature to document");
            document.addSignature(signature);
            logger.info("Saving document for external signing");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(baos);
            logger.info("Signing PDF with Bouncy Castle");
            byte[] cmsSignature = signPdfWithBouncyCastle(externalSigning.getContent(), privateKey, certificateChain);
            logger.info("Setting signature");
            externalSigning.setSignature(cmsSignature);
            logger.info("PDF signing process completed successfully");
            return baos.toByteArray();
        } catch (Exception e) {
            logger.error("Error signing PDF", e);
            throw e;
        }
    }

    private byte[] signPdfWithBouncyCastle(InputStream content, PrivateKey privateKey, Certificate[] certificateChain) throws Exception {
        try {
            logger.info("Starting Bouncy Castle signing process");
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate cert = (X509Certificate) certificateChain[0];
            logger.info("Creating content signer");
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
            logger.info("Adding signer info generator");
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, cert));
            logger.info("Adding certificates");
            gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));
            logger.info("Creating CMS typed data");
            CMSTypedData msg = new CMSProcessableByteArray(IOUtils.toByteArray(content));
            logger.info("Generating CMS signed data");
            CMSSignedData signedData = gen.generate(msg, false);
            logger.info("Bouncy Castle signing process completed successfully");
            return signedData.getEncoded();
        } catch (Exception e) {
            logger.error("Error in Bouncy Castle signing process", e);
            throw e;
        }
    }

    private String uploadToS3AndGenerateUrl(byte[] pdfBytes, String fileName) {
        try {
            logger.info("Uploading PDF to S3: {}", fileName);
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(fileName)
                    .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromBytes(pdfBytes));
            logger.info("PDF uploaded successfully to S3");

            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(fileName)
                    .build();

            GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder()
                    .signatureDuration(Duration.ofMinutes(10))
                    .getObjectRequest(getObjectRequest)
                    .build();

            String presignedUrl = s3Presigner.presignGetObject(presignRequest).url().toString();
            logger.info("Presigned URL generated: {}", presignedUrl);

            return presignedUrl;
        } catch (Exception e) {
            logger.error("Error uploading PDF to S3 or generating presigned URL", e);
            throw new RuntimeException("Failed to upload PDF to S3 or generate presigned URL", e);
        }
    }
}
