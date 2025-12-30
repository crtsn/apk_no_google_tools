import com.reandroid.apk.AndroidFrameworks;
import com.reandroid.apk.ApkModule;
import com.reandroid.apk.APKLogger;
import com.reandroid.apk.FrameworkApk;
import com.reandroid.archive.ByteInputSource;
import com.reandroid.arsc.chunk.PackageBlock;
import com.reandroid.arsc.chunk.TableBlock;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import com.reandroid.arsc.chunk.xml.ResXmlAttribute;
import com.reandroid.arsc.chunk.xml.ResXmlElement;
import com.reandroid.arsc.coder.EncodeResult;
import com.reandroid.arsc.coder.ValueCoder;
import com.reandroid.arsc.value.Entry;
import com.reandroid.archive.WriteProgress;
import com.reandroid.arsc.chunk.xml.ResXmlDocument;
import org.xmlpull.v1.XmlPullParserException;
import com.reandroid.xml.source.XMLParserSource;
import com.reandroid.xml.source.XMLFileParserSource;
import org.xmlpull.v1.XmlPullParser;
import com.reandroid.app.AndroidManifest;
import com.reandroid.utils.io.IOUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException, XmlPullParserException {

		if (args.length < 2)
		{
			System.out.println("Usage: java -jar altaapt <AndroidXmlPath> <AndroidBinXmlPath>");
			System.exit(1);
		}

        ApkModule apkModule = new ApkModule();
		apkModule.setAPKLogger(new APKLogger() {
			public void logMessage(String msg)
			{
				System.out.println("LOG: " + msg);
			}

			public void logError(String msg, Throwable tr)
			{
				System.out.println("ERROR: " + msg + ": " + tr.toString());
			}

			public void logVerbose(String msg)
			{
				System.out.println("VERBOSE: " + msg);
			}
		});

        TableBlock tableBlock = new TableBlock();
        AndroidManifestBlock manifest = new AndroidManifestBlock();

        apkModule.setTableBlock(tableBlock);
        apkModule.setManifest(manifest);

        FrameworkApk framework = apkModule.initializeAndroidFramework(
                AndroidFrameworks.getLatest().getVersionCode());

        PackageBlock packageBlock = tableBlock.newPackage(0x7f, "com.example.test");

		File manifestFile = new File(args[0]);
		XMLParserSource parserSource =
                new XMLFileParserSource(AndroidManifestBlock.FILE_NAME, manifestFile);
        String path = parserSource.getPath();
        System.out.println("Encoding: " + path);
        XmlPullParser parser = parserSource.getParser();
        manifest.setPackageBlock(tableBlock.pickOne());
        manifest.parse(parser);
		// not sure why it adds package name and not replaces it 
        // manifest.setPackageName("com.BOOP");
        IOUtil.close(parser);

		System.out.println("ENCODE: " + manifest.serializetoxml());
		FileOutputStream fos = new FileOutputStream(args[1]);
		manifest.writeBytes(fos);
    }
}
