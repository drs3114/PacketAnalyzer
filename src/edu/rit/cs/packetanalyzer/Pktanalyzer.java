/**
 * 
 */
package edu.rit.cs.packetanalyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * This is the analyzer that analyzes TCP, UDP, ICMP, IP, Ethernet packets and
 * displays the related information to the user in a user readable and
 * understandable format.</br>
 * For more information, see
 * {@link https://www.cs.rit.edu/~jmk/csci651/proj/packet.html}</br>
 * usage: {@code java Pktanalyser <packet.bin>}
 * 
 * @author Deepak Ravi Shankar
 * @version 1.2.1
 * @since September 7, 2016
 * 
 */
public class Pktanalyzer {
	String dataFileName;
	File packetFile;
	Pkt packet;

	/**
	 * This is a parameterized constructor for constructing a
	 * {@code Pktanalyzer} object to analyze the packet.
	 * 
	 * @param string
	 */
	public Pktanalyzer(String string) {
		this.dataFileName = string;
		try {
			this.packetFile = new File(dataFileName);

		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}

	/**
	 * This method is used to get the string representation of the
	 * {@code Pktanalyzer} class.</br>
	 * Here, this function gives the name of the file this analyser is currently
	 * working on.
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "Analyser for the packet " + dataFileName;
	}

	/**
	 * This is the method to analyze the given packet.
	 */
	public void analyze() {
		InputStream inputStream = null;

		try {
			inputStream = new FileInputStream(packetFile);
			byte[] data = new byte[inputStream.available()];
			inputStream.read(data);
			packet = new Pkt(data);
			System.out.println(packet);
		} catch (FileNotFoundException e) {

			e.printStackTrace();
		} catch (IOException e) {

			e.printStackTrace();
		} finally {
			try {
				if (inputStream != null) {

					inputStream.close();

				}
			} catch (IOException e) {

				e.printStackTrace();
			}
		}

	}

	/**
	 * This is the main program. The control flow of the programs starts from
	 * this function.
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		if (!(args.length > 0)) {
			System.out.println("Usage: java pktanalyser datafile");
			System.exit(1);
		} else {
			Pktanalyzer analyzer = new Pktanalyzer(args[0]);
			analyzer.analyze();

		}

	}

}
