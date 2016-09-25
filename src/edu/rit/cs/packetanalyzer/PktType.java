/**
 * 
 */
package edu.rit.cs.packetanalyzer;

/**
 * This is an enumeration class to map the different packet types.
 * 
 * @author Deepak Ravi Shankar
 * @version 1.0.0
 */
public enum PktType {
	ICMP("ICMP", 1), IGMP("IGMP", 2), TCP("TCP", 6), UDP("UDP", 17), ENCAP("ENCAP", 41), OSPF("OSPF", 89), SCTP("SCTP",
			132), TEAPOT("TEAPOT", 9999);

	// this is the string to be displayed when enumeration is refereed to be
	// displayed.
	private String displayName;

	// this is the id that uniquely represents the each enumeration.
	private int id;

	// This is a constructor to create an enumeration.
	private PktType(final String displayName, final int id) {
		this.displayName = displayName;
		this.id = id;

	}

	/**
	 * This is method is used to get the string reprenation of the enumeration.
	 * 
	 * @return the displayName
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * This method is used to get the id of an enumeration.
	 * 
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * This method is used to get the name of the enumeration.
	 * 
	 * @return name
	 */
	public String getName() {
		return this.name();
	}

}
