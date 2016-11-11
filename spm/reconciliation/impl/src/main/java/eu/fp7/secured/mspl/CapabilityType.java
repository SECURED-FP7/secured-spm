//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.20 at 05:38:59 PM CEST 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CapabilityType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="CapabilityType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Filtering_L4"/>
 *     &lt;enumeration value="Filtering_L7"/>
 *     &lt;enumeration value="Timing"/>
 *     &lt;enumeration value="TrafficInspection_L7"/>
 *     &lt;enumeration value="Filtering_3G4G"/>
 *     &lt;enumeration value="Filtering_DNS"/>
 *     &lt;enumeration value="Offline_malware_analysis"/>
 *     &lt;enumeration value="Online_SPAM_analysis"/>
 *     &lt;enumeration value="Online_antivirus_analysis"/>
 *     &lt;enumeration value="Network_traffic_analysis"/>
 *     &lt;enumeration value="DDos_attack_protection"/>
 *     &lt;enumeration value="lawful_interception"/>
 *     &lt;enumeration value="Count_L4Connection"/>
 *     &lt;enumeration value="Count_DNS"/>
 *     &lt;enumeration value="Protection_confidentiality"/>
 *     &lt;enumeration value="Protection_integrity"/>
 *     &lt;enumeration value="Compress"/>
 *     &lt;enumeration value="Logging"/>
 *     &lt;enumeration value="AuthoriseAccess_resurce"/>
 *     &lt;enumeration value="Reduce_bandwidth"/>
 *     &lt;enumeration value="Online_security_analyzer"/>
 *     &lt;enumeration value="Basic_parental_control"/>
 *     &lt;enumeration value="Advanced_parental_control"/>
 *     &lt;enumeration value="IPSec_protocol"/>
 *     &lt;enumeration value="TLS_protocol"/>
 *     &lt;enumeration value="reencrypt"/>
 *     &lt;enumeration value="antiPhishing"/>
 *     &lt;enumeration value="anonimity"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "CapabilityType")
@XmlEnum
public enum CapabilityType {

    @XmlEnumValue("Filtering_L4")
    FILTERING_L_4("Filtering_L4"),
    @XmlEnumValue("Filtering_L7")
    FILTERING_L_7("Filtering_L7"),
    @XmlEnumValue("Timing")
    TIMING("Timing"),
    @XmlEnumValue("TrafficInspection_L7")
    TRAFFIC_INSPECTION_L_7("TrafficInspection_L7"),
    @XmlEnumValue("Filtering_3G4G")
    FILTERING_3_G_4_G("Filtering_3G4G"),
    @XmlEnumValue("Filtering_DNS")
    FILTERING_DNS("Filtering_DNS"),
    @XmlEnumValue("Offline_malware_analysis")
    OFFLINE_MALWARE_ANALYSIS("Offline_malware_analysis"),
    @XmlEnumValue("Online_SPAM_analysis")
    ONLINE_SPAM_ANALYSIS("Online_SPAM_analysis"),
    @XmlEnumValue("Online_antivirus_analysis")
    ONLINE_ANTIVIRUS_ANALYSIS("Online_antivirus_analysis"),
    @XmlEnumValue("Network_traffic_analysis")
    NETWORK_TRAFFIC_ANALYSIS("Network_traffic_analysis"),
    @XmlEnumValue("DDos_attack_protection")
    D_DOS_ATTACK_PROTECTION("DDos_attack_protection"),
    @XmlEnumValue("lawful_interception")
    LAWFUL_INTERCEPTION("lawful_interception"),
    @XmlEnumValue("Count_L4Connection")
    COUNT_L_4_CONNECTION("Count_L4Connection"),
    @XmlEnumValue("Count_DNS")
    COUNT_DNS("Count_DNS"),
    @XmlEnumValue("Protection_confidentiality")
    PROTECTION_CONFIDENTIALITY("Protection_confidentiality"),
    @XmlEnumValue("Protection_integrity")
    PROTECTION_INTEGRITY("Protection_integrity"),
    @XmlEnumValue("Compress")
    COMPRESS("Compress"),
    @XmlEnumValue("Logging")
    LOGGING("Logging"),
    @XmlEnumValue("AuthoriseAccess_resurce")
    AUTHORISE_ACCESS_RESURCE("AuthoriseAccess_resurce"),
    @XmlEnumValue("Reduce_bandwidth")
    REDUCE_BANDWIDTH("Reduce_bandwidth"),
    @XmlEnumValue("Online_security_analyzer")
    ONLINE_SECURITY_ANALYZER("Online_security_analyzer"),
    @XmlEnumValue("Basic_parental_control")
    BASIC_PARENTAL_CONTROL("Basic_parental_control"),
    @XmlEnumValue("Advanced_parental_control")
    ADVANCED_PARENTAL_CONTROL("Advanced_parental_control"),
    @XmlEnumValue("IPSec_protocol")
    IP_SEC_PROTOCOL("IPSec_protocol"),
    @XmlEnumValue("TLS_protocol")
    TLS_PROTOCOL("TLS_protocol"),
    @XmlEnumValue("reencrypt")
    REENCRYPT("reencrypt"),
    @XmlEnumValue("antiPhishing")
    ANTI_PHISHING("antiPhishing"),
    @XmlEnumValue("anonimity")
    ANONIMITY("anonimity");
    private final String value;

    CapabilityType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static CapabilityType fromValue(String v) {
        for (CapabilityType c: CapabilityType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
