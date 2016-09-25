/**
 * 
 */
package edu.rit.cs.packetanalyzer;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This is a encapsulation of a network packet that holds information and
 * functionalities related to bytes within the packet.
 * 
 * @author Deepak Ravi Shankar
 * @version 1.2.1
 * @since September 13, 2016
 *
 */
public class Pkt {

	private byte[] contents;
	private byte[] ethernetHeader;
	private byte[] ipHeader;
	private byte[] protocolSpecificData;
	private PktType type;

	/**
	 * @return the contents
	 */
	public byte[] getContents() {
		return contents;
	}

	/**
	 * @param contents
	 *            the contents to set
	 */
	public void setContents(byte[] contents) {
		this.contents = contents;
	}

	/**
	 * @return the ethernetHeader
	 */
	public byte[] getEthernetHeader() {
		return ethernetHeader;
	}

	/**
	 * @param ethernetHeader
	 *            the ethernetHeader to set
	 */
	public void setEthernetHeader(byte[] ethernetHeader) {
		this.ethernetHeader = ethernetHeader;
	}

	/**
	 * @return the ipHeader
	 */
	public byte[] getIpHeader() {
		return ipHeader;
	}

	/**
	 * @param ipHeader
	 *            the ipHeader to set
	 */
	public void setIpHeader(byte[] ipHeader) {
		this.ipHeader = ipHeader;
	}

	/**
	 * @return the protocolSpecificData
	 */
	public byte[] getProtocolSpecificData() {
		return protocolSpecificData;
	}

	/**
	 * @param protocolSpecificData
	 *            the protocolSpecificData to set
	 */
	public void setProtocolSpecificData(byte[] protocolSpecificData) {
		this.protocolSpecificData = protocolSpecificData;
	}

	/**
	 * @return the type
	 */
	public PktType getType() {
		return type;
	}

	/**
	 * @param type
	 *            the type to set
	 */
	public void setType(PktType type) {
		this.type = type;
	}

	/**
	 * This is a constructor for the {@code Pkt} class objects used to construct
	 * objects with packet information stored in byte array.
	 * 
	 * @param contents
	 */
	public Pkt(byte[] contents) {
		if (contents.length >= 34) {
			this.contents = new byte[contents.length];
			this.ethernetHeader = new byte[14];
			this.ipHeader = new byte[20];
			this.contents = contents;
			for (int i = 0; i < 14; i++) {
				this.ethernetHeader[i] = this.contents[i];
			}
			for (int i = 0, j = 14; i < 20 && j < 34; i++, j++) {
				this.ipHeader[i] = this.contents[j];
			}

			this.protocolSpecificData = new byte[this.contents.length - 34];
			for (int i = 0, j = 34; j < contents.length; i++, j++) {
				this.protocolSpecificData[i] = this.contents[j];
			}

			switch (Integer.parseInt(String.format("%02x", ipHeader[9]), 16)) {
			case 1:
				this.setType(PktType.ICMP);
				break;
			case 17:
				this.setType(PktType.UDP);
				break;
			case 6:
				this.setType(PktType.TCP);
				break;
			default:
				this.setType(PktType.TEAPOT);

			}
		} else {
			System.err.println("Corrupt packet!!!");
			System.exit(-1);
		}
	}

	/**
	 * This method is used to get a string representation of a specified packet.
	 * The string representation gets all the specific information related to
	 * that packet and presents it to the user in a readable format.</br>
	 * This methods overrides the <i> toString() </i> method in the
	 * {@code Object} class.
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String result = "";
		result = result + getEthernetHeaderDetails();
		result = result + getIpHeaderDetails();
		switch (this.type) {
		case ICMP:
			result = result + getICMPDetails();
			break;
		case TCP:
			result = result + getTCPDetails();
			break;
		case UDP:
			result = result + getUDPDetails();
			break;
		case IGMP:
		case ENCAP:
		case OSPF:
		case SCTP:
		case TEAPOT:
			break;
		}
		return result;

	}

	/**
	 * This method is used by the <i> toString() </i> method of the {@code Pkt}
	 * class. This is a private method and is used in getting the
	 * <b><i> Ethernet </i></b> related header information from the given
	 * packet.
	 * 
	 * @return String representation of the Ethernet header of the packet.
	 */
	private String getEthernetHeaderDetails() {
		String result = "ETHER:  ----- Ether Header ----- \n";
		result = result + "ETHER: \nETHER:  Packet size = " + this.contents.length + " bytes" + "\n";
		result = result + "ETHER:  Destination = " + String.format("%02x", ethernetHeader[0]) + ":"
				+ String.format("%02x", ethernetHeader[1]) + ":" + String.format("%02x", ethernetHeader[2]) + ":"
				+ String.format("%02x", ethernetHeader[3]) + ":" + String.format("%02x", ethernetHeader[4]) + ":"
				+ String.format("%02x", ethernetHeader[5]) + ",\n";
		result = result + "ETHER:  Source      = " + String.format("%02x", ethernetHeader[6]) + ":"
				+ String.format("%02x", ethernetHeader[7]) + ":" + String.format("%02x", ethernetHeader[8]) + ":"
				+ String.format("%02x", ethernetHeader[9]) + ":" + String.format("%02x", ethernetHeader[10]) + ":"
				+ String.format("%02x", ethernetHeader[11]) + ",\n";
		result = result + "ETHER:  Ethertype = " + String.format("%02x", ethernetHeader[12])
				+ String.format("%02x", ethernetHeader[13]) + " (IP)\nETHER: \n";
		return result;

	}

	/**
	 * This method is used by the <i> toString() </i> method of the {@code Pkt}
	 * class. This is a private method and is used in getting the
	 * <b><i> IP </i></b> related header information from the given packet.
	 * 
	 * @return String representation of the IP header of the packet.
	 */
	private String getIpHeaderDetails() {

		String result = "IP:   ----- IP Header ----- \nIP:\n";
		result = result + "IP:   Version = " + (String.format("%02x", ipHeader[0])).substring(0, 1) + "\n";
		result = result + "IP:   Header length = " + getIPHeaderLength(ipHeader[0]) + " bytes\n";
		result = result + "IP:   Type of service = 0x" + String.format("%02x", ipHeader[1]) + "\n";
		result = result + "IP:         xxx. .... = 0 (precedence)\n";

		String servicestr = String.format("%02x", ipHeader[1]);
		servicestr = new BigInteger(servicestr, 16).toString(2);
		int[] services = new int[8];
		for (int i = 0; i < servicestr.length(); i++) {
			services[i] = servicestr.charAt(i) - '0';
		}

		if (services[3] == 1) {
			result = result + "IP:         ...1 .... = low delay\n";
		} else {
			result = result + "IP:         ...0 .... = normal delay\n";
		}
		if (services[4] == 1) {
			result = result + "IP:         .... 1... = high throughput\n";
		} else {
			result = result + "IP:         .... 0... = normal throughput \n";
		}
		if (services[5] == 1) {
			result = result + "IP:         .... .1.. = high reliability \n";
		} else {
			result = result + "IP:         .... .0.. = normal reliability \n";
		}

		result = result + "IP:   Total length = "
				+ String.valueOf(Integer.valueOf(String.format("%02x", ipHeader[3]), 16)) + " bytes\n";
		result = result + "IP:   Identification = "
				+ String.valueOf(
						Long.valueOf(String.format("%02x", ipHeader[4]) + String.format("%02x", ipHeader[5]), 16))
				+ "\n";
		String flagstr = String.format("%02x", ipHeader[6]);
		flagstr = new BigInteger(flagstr, 16).toString(2);
		int[] flags = new int[8];
		for (int i = 0; i < flagstr.length(); i++) {
			flags[i] = flagstr.charAt(i) - '0';
		}

		result = result + "IP:   Flags = 0x" + String.format("%02x", ipHeader[6]).substring(0, 1) + "\n";
		if (flags[1] == 1) {
			result = result + "IP:         .1.. .... = do not fragment \n";
		} else {
			result = result + "IP:         .0.. .... = do not fragment \n";
		}
		if (flags[2] == 1) {
			result = result + "IP:         ..1. .... = last fragment \n";
		} else {
			result = result + "IP:         ..0. .... = last fragment \n";
		}
		result = result + "IP:   Fragment offset = "
				+ String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[7]), 16)) + "\n";
		result = result + "IP:   Time to live = "
				+ String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[8]), 16)) + " seconds/hops \n";
		result = result + "IP:   Protocol = " + String.valueOf(this.getType().getId()) + " ("
				+ this.getType().getDisplayName() + ")\n";
		result = result + "IP:   Header checksum = " + String.format("%02x", ipHeader[10])
				+ String.format("%02x", ipHeader[11]) + "\n";
		result = result + "IP:   Source address = " + getSourceAddress() + "\n";
		result = result + "IP:   Destination address = " + getDestinationAddress() + "\n";
		result = result + "IP:   No options\nIP:\n";
		return result;
	}

	/**
	 * This method is used by the <i> toString() </i> method of the {@code Pkt}
	 * class. This is a private method and is used in getting the
	 * <b><i> UDP </i></b> related header information from the given packet.
	 * 
	 * @return String representation of the UDP related header information of
	 *         the packet.
	 */
	private String getUDPDetails() {
		String result = "UDP:  ----- UDP Header -----\nUDP: \n";
		String sourcePort = String.valueOf(Integer.valueOf(
				String.format("%02x", protocolSpecificData[0]) + String.format("%02x", protocolSpecificData[1]), 16));
		String destPort = String.valueOf(Integer.valueOf(
				String.format("%02x", protocolSpecificData[2]) + String.format("%02x", protocolSpecificData[3]), 16));
		String length = String.valueOf(Integer.valueOf(
				String.format("%02x", protocolSpecificData[4]) + String.format("%02x", protocolSpecificData[5]), 16));
		result = result + "UDP:  Source port = " + sourcePort + "\n";
		result = result + "UDP:  Destination port = " + destPort + " (NFS)\n";
		result = result + "UDP:  Length = " + length + "\n";
		result = result + "UDP:  Checksum = " + String.format("%02x", protocolSpecificData[6])
				+ String.format("%02x", protocolSpecificData[7]) + "\nUDP:\n";
		result = result + getData("UDP");

		return result;
	}

	/**
	 * This method is used by the <i> toString() </i> method of the {@code Pkt}
	 * class. This is a private method and is used in getting the
	 * <b><i> TCP </i></b> related header information from the given packet.
	 * 
	 * @return String representation of the TCP related header information of
	 *         the packet.
	 */
	private String getTCPDetails() {
		String result = "TCP:  ----- TCP Header -----\nTCP: \n";

		String sourcePort = String.valueOf(Long.valueOf(
				String.format("%02x", protocolSpecificData[0]) + String.format("%02x", protocolSpecificData[1]), 16));
		String destPort = String.valueOf(Long.valueOf(
				String.format("%02x", protocolSpecificData[2]) + String.format("%02x", protocolSpecificData[3]), 16));
		String sequenceNumber = String.valueOf(Long.valueOf(String.format("%02x", protocolSpecificData[4])
				+ String.format("%02x", protocolSpecificData[5]) + String.format("%02x", protocolSpecificData[6])
				+ String.format("%02x", protocolSpecificData[7]), 16));
		String ackNumber = String.valueOf(Long.valueOf(String.format("%02x", protocolSpecificData[8])
				+ String.format("%02x", protocolSpecificData[9]) + String.format("%02x", protocolSpecificData[10])
				+ String.format("%02x", protocolSpecificData[11]), 16));

		result = result + "TCP:  Source port = " + sourcePort + "\n";
		result = result + "TCP:  Destination port = " + destPort + " (NFS)\n";
		result = result + "TCP:  Sequence number = " + sequenceNumber + "\n";
		result = result + "TCP:  Acknowledgement number = " + ackNumber + "\n";
		int dataOffset = 4 * Integer.parseInt((String.format("%02x", protocolSpecificData[12])).substring(0, 1), 16);

		result = result + "TCP:  Data offset = " + String.valueOf(dataOffset) + " bytes\n";
		result = result + "TCP:  Flags = 0x" + String.format("%02x", protocolSpecificData[13]) + "\n";

		String flagstr = String.format("%02x", protocolSpecificData[13]);
		flagstr = new BigInteger(flagstr, 16).toString(2);
		int[] flags = new int[8];
		for (int i = 0; i < flagstr.length(); i++) {
			flags[i] = flagstr.charAt(i) - '0';
		}

		if (flags[2] == 1) {
			result = result + "TCP:        ..1. .... = Urgent pointer \n";
		} else {
			result = result + "TCP:        ..0. .... = No urgent pointer \n";
		}
		if (flags[3] == 1) {
			result = result + "TCP:        ...1 .... = Acknowledgement\n";
		} else {
			result = result + "TCP:        ...0 .... = No Acknowledgement\n";
		}
		if (flags[4] == 1) {
			result = result + "TCP:        .... 1... = Push \n";
		} else {
			result = result + "TCP:        .... 0... = No Push \n";
		}
		if (flags[5] == 1) {
			result = result + "TCP:        .... .1.. = Reset \n";
		} else {
			result = result + "TCP:        .... .0.. = No Reset \n";
		}
		if (flags[6] == 1) {
			result = result + "TCP:        .... ..1. = Syn \n";
		} else {
			result = result + "TCP:        .... ..0. = No Syn \n";
		}
		if (flags[7] == 1) {
			result = result + "TCP:        .... ...1 = Fin \n";
		} else {
			result = result + "TCP:        .... ...0 = No Fin \n";
		}

		result = result + "TCP:  Window = " + String.valueOf(Long.valueOf(
				String.format("%02x", protocolSpecificData[14]) + String.format("%02x", protocolSpecificData[15]), 16))
				+ "\n";
		result = result + "TCP:  Checksum = 0x" + String.format("%02x", protocolSpecificData[16])
				+ String.format("%02x", protocolSpecificData[17]) + "\n";
		result = result + "TCP:  Urgent pointer = " + String.valueOf(Long.valueOf(
				String.format("%02x", protocolSpecificData[18]) + String.format("%02x", protocolSpecificData[19]), 16))
				+ "\n";
		result = result + "TCP:  No options \nTCP: \n";
		result = result + getData("TCP");

		return result;
	}

	/**
	 * This method is used by the <i> toString() </i> method of the {@code Pkt}
	 * class. This is a private method and is used in getting the
	 * <b><i> ICMP </i></b> related header information from the given packet.
	 * 
	 * @return String representation of the ICMP related header information of
	 *         the packet.
	 */
	private String getICMPDetails() {
		String result = "ICMP:  ----- ICMP Header -----\nICMP: \n";
		result = result + "ICMP:  Type = "
				+ String.valueOf(Integer.parseInt(String.format("%02x", protocolSpecificData[0]), 16))
				+ " (Echo request)\n";
		result = result + "ICMP:  Code = "
				+ String.valueOf(Integer.valueOf(String.format("%02x", protocolSpecificData[1]), 16)) + "\n";
		result = result + "ICMP:  Checksum = " + String.format("%02x", protocolSpecificData[2])
				+ String.format("%02x", protocolSpecificData[3]) + "\nICMP:\n";

		return result;
	}

	/**
	 * This method is used by the <i> getIpHeaderDetails() </i> method of the
	 * {@code Pkt} class. This is a private method and is used in getting the
	 * <b><i> Destination Address. </i></b>
	 * 
	 * @return String representation of the Destination address.
	 */
	private String getDestinationAddress() {
		String sourceIP = String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[12]), 16)) + "."
				+ String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[13]), 16)) + "."
				+ String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[14]), 16)) + "."
				+ String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[15]), 16));
		InetAddress address = null;
		try {
			address = InetAddress.getByName(sourceIP);
		} catch (UnknownHostException e) {

			e.printStackTrace();
		}
		String result = sourceIP + ", ";
		if (address == null) {
			result = result + "(hostname unknown)";
		} else {
			result = result + address.getHostName();
		}

		return result;
	}

	/**
	 * This method is used by the <i> getIpHeaderDetails() </i> method of the
	 * {@code Pkt} class. This is a private method and is used in getting the
	 * <b><i> Source Address. </i></b>
	 * 
	 * @return String representation of the Source address.
	 */
	private String getSourceAddress() {
		String destinationIP = String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[16]), 16)) + "."
				+ String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[17]), 16)) + "."
				+ String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[18]), 16)) + "."
				+ String.valueOf(Integer.parseInt(String.format("%02x", ipHeader[19]), 16));
		InetAddress address = null;
		try {
			address = InetAddress.getByName(destinationIP);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		String result = destinationIP + ", ";
		if (address == null) {
			result = result + "(hostname unknown)";
		} else {
			result = result + address.getHostName();
		}

		return result;

	}

	/**
	 * This method is used by the <i> getIpHeaderDetails() </i> method of the
	 * {@code Pkt} class. This is a private method and is used in getting the
	 * <b><i> IP header details </i></b>
	 * 
	 * @return String representation of the IP header details.
	 */
	private String getIPHeaderLength(byte b) {
		int length = 4;
		String info = String.format("%02x", b);
		String len = info.substring(1, 2);
		length = length * Integer.parseInt(len);
		String result = String.valueOf(length);
		return result;

	}

	/**
	 * This method is used by {@code getTCPDetails()} and
	 * {@code getUDPDetails()} methods to ge the data encapsulated in the
	 * respective TCP and UDP packets.
	 * 
	 * @param protocol
	 *            The name of the protocol for which this method is called.
	 * @return String representation of the data encapsulated in the TCP/UDP
	 *         packet.
	 */
	private String getData(String protocol) {
		String result = protocol + ":  Data: (first 64 bytes) \n";
		int j = 20;
		byte[] data;
		for (int i = 0; i < 4 && j < protocolSpecificData.length; i++) {
			result = result + protocol + ":  ";
			int counter = 0;
			data = new byte[20];
			while (counter < 16 && j < protocolSpecificData.length) {
				result = result + String.format("%02x", protocolSpecificData[j]);
				data[counter] = protocolSpecificData[j];
				counter++;
				if (j % 2 != 0)
					result = result + " ";
				j++;
			}
			result = result + decodeData(data);
			data = null;
			result = result + "\n";
		}
		return result;
	}

	/**
	 * This method is used by {@code getData()} method. This method decodes the
	 * ASCII from the binary representation of the bytes and presents a readable
	 * format to the user.
	 * 
	 * @param data
	 *            The byte stream to be decoded sent in binary.
	 * @return The ASCII values based on the binary data present in the data
	 *         byte stream.
	 */
	private String decodeData(byte[] data) {
		String result = "";
		if (data != null) {
			result = "    \"";
			int ch;// = Integer.parseInt("%02x", data[i])
			for (byte b : data) {
				ch = Integer.parseInt(String.format("%02x", b), 16);
				if (ch >= 33 && ch <= 126) {
					result = result + (char) ch;
				} else {
					result = result + ".";
				}
			}
			result = result + "\"";

		}
		return result;
	}

	/**
	 * This method is used for debugging purposes.</br>
	 * This methods prints the Hexadecimal representation of the binary data
	 * stored in the byte array.
	 * 
	 * @param bytes
	 *            The array whose hexadecimal representation is needed.
	 * @param name
	 *            The name to be printed for a better understanding of the byte
	 *            array.
	 */
	@SuppressWarnings("unused")
	private void print(byte[] bytes, String name) {
		System.out.println("/////////////////" + name + "////////////////");
		for (int i = 0; i < bytes.length; i++)
			System.out.println(String.format("%02x", bytes[i]));
		System.out.println("/////////////////////////////////////////////");
	}

}
