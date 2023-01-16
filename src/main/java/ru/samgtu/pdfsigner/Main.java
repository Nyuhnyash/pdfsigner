package ru.samgtu.pdfsigner;

import com.itextpdf.io.font.PdfEncodings;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Help.Visibility;
import picocli.CommandLine.Option;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Objects;

@Command(name = "pdf-signer-gost", version = "1.0",
		description = "PDF signing tool, requires itext7 and Bouncy Castle CryptoProvider.",
		separator = " ", mixinStandardHelpOptions = true, sortOptions = false, usageHelpAutoWidth = true)
public class Main implements Runnable {

	@Option(names = "--from", description = "Source directory", defaultValue = ".", showDefaultValue = Visibility.ALWAYS) static File sourceDirectory;
	@Option(names = "--to", description = "Target directory", defaultValue = "signed", showDefaultValue = Visibility.ALWAYS) static File targetDirectory;
	@Option(names = "--pfx", description = "PKCS12 (.pfx, .p12) certificate and private key container file", defaultValue = "cert.pfx", showDefaultValue = Visibility.ALWAYS) static File pkcs12File;
	@Option(names = "--pass", description = "PFX file password") static char[] pkcs12Password = "123456".toCharArray();
	@Option(names = "--position", description = "Visible signature position") static Rectangle position /*= new Rectangle(100, 585, 200, 100)*/;
	@Option(names = "--reason", description = "Sign reason") static String reason = "";
	@Option(names = "--location", description = "Sign location") static String location = "";
	@Option(names = "--contact", description = "Signer contact") static String contact = "";


	public static void main(String[] args) {
		var commandLine = new CommandLine(new Main());
		commandLine.registerConverter(Rectangle.class, value -> {
			var e = value.split(",");
			if (e.length != 4) {
				throw new IllegalArgumentException("4 integers required");
			}
			return new Rectangle(Integer.parseInt(e[0]), Integer.parseInt(e[1]), Integer.parseInt(e[2]), Integer.parseInt(e[3]));
		});

		commandLine.execute(args);
	}

	@Override
	public void run() {
		validate();

		Security.addProvider(new BouncyCastleProvider());

		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
			keyStore.load(new FileInputStream(pkcs12File), pkcs12Password);

			var alias = keyStore.aliases().nextElement();
			var key = (PrivateKey) keyStore.getKey(alias, pkcs12Password);
			var chain = keyStore.getCertificateChain(alias);

			var sigAlgName = ((X509Certificate) chain[0]).getSigAlgName();
			var hashAlgorithm = sigAlgName.split("WITH")[0];

			if (key == null)
				throw new RuntimeException("Failed to get key from the keystore");


			var externalSignature = new PrivateKeySignature(key, hashAlgorithm, "BC");
			if (externalSignature.getHashAlgorithm() == null)
				throw new RuntimeException("No usable hash algorithm found");

			System.out.printf("Hash Algorithm:       %s\n", externalSignature.getHashAlgorithm());
			System.out.printf("Encryption Algorithm: %s\n", externalSignature.getEncryptionAlgorithm());

			// workaround
			// Bouncy Castle определяет ключ как GOST3410-2012 без указания размера блока
			// Signature.getInstance() не находит GOST3411-2012-256WITHECGOST3410-2012
			// Known signature algorithms: GOST3411-2012-256WITHECGOST3410-2012-256
			//                             GOST3411-2012-512WITHECGOST3410-2012-512
			if (key instanceof BCECGOST3410_2012PrivateKey) {
				var gostKey = (BCECGOST3410_2012PrivateKey) key;
				var is512 = gostKey.getD().bitLength() > 256;

				externalSignature.setHashAlgorithm("GOST3411-2012-" + (is512 ? "512" : "256")); // CryptoPro workaround

				externalSignature.setEncryptionAlgorithm("ECGOST3410-2012-" + (is512 ? "512" : "256"));
			}

			var digest = new BouncyCastleDigest();

			for (var file : Objects.requireNonNull(sourceDirectory.listFiles(File::isFile))) {
				if (file.getName().endsWith(".pdf")) {
					sign(file, new File(targetDirectory, file.getName()), digest, externalSignature, chain);
				}
			}
		} catch (GeneralSecurityException | IOException e) {
			throw new RuntimeException(e);
		}
	}

	public void sign(File pdfFile, File outputFilename, IExternalDigest digest, IExternalSignature externalSignature, Certificate[] chain)
			throws IOException, GeneralSecurityException {
		var pdfSigner = new PdfSigner(
				new PdfReader(pdfFile),
				new FileOutputStream(outputFilename),
				new StampingProperties());

		var signDateTime = new SimpleDateFormat("dd.MM.yyyy k:m").format(pdfSigner.getSignDate().getTime());
		var subjectName = ((X509Certificate) chain[0]).getSubjectX500Principal().getName();

		var text = String.format(
				"Signed with electronic signature\n" +
				"Date: %s\n" +
				"Subject: %s",
				signDateTime, subjectName);

		var r = ClassLoader.getSystemClassLoader().getResourceAsStream("FreeSans-LrmZ.ttf");
		// Java >= 9
		// byte[] fontBytes = r.readAllBytes();

		// Java < 9
		byte[] buffer = new byte[1000];
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		int temp;
		while ((temp = r.read(buffer)) != -1) {
			byteArrayOutputStream.write(buffer, 0, temp);
		}
		byte[] fontBytes = byteArrayOutputStream.toByteArray();
		//

		if (position != null) {
			var sap = pdfSigner.getSignatureAppearance();
			sap.setPageRect(position);
			sap.setReason(reason);
			sap.setLocation(location);
			sap.setContact(contact);
			sap.setLayer2Text(text);
			sap.setLayer2Font(PdfFontFactory.createFont(fontBytes, PdfEncodings.IDENTITY_H, PdfFontFactory.EmbeddingStrategy.FORCE_EMBEDDED));
		}

		pdfSigner.signDetached(digest, externalSignature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

		System.out.printf("%s: Done.\n", pdfFile.getName());
	}

	public void validate() {
		var pkcs12FileName = pkcs12File.getName();
		if (!pkcs12FileName.endsWith(".pfx") && !pkcs12FileName.endsWith(".p12"))
			throw new RuntimeException("PKCS12 Container should have .pfx or .p12 extension");
		if (!pkcs12File.exists()) throw new RuntimeException("PFX not found");
		if (!pkcs12File.isFile()) throw new RuntimeException("PFX parameter isn't a file");

		if (!sourceDirectory.exists()) throw new RuntimeException("Source directory not found");
		if (!sourceDirectory.isDirectory()) throw new RuntimeException("Source is not a directory");

		if (!targetDirectory.exists() && !targetDirectory.mkdir())
			throw new RuntimeException("Can't create target directory");
		if (!targetDirectory.isDirectory()) throw new RuntimeException("Target is not a directory");
	}
}
