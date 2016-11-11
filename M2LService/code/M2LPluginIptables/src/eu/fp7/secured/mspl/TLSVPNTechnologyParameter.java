//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.11.18 at 02:29:52 PM CET 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for TLS_VPN_TechnologyParameter complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TLS_VPN_TechnologyParameter">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}TechnologySpecificParameters">
 *       &lt;sequence>
 *         &lt;element name="peerPort" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="L4Protocol" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="localEndpoint" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="remoteEndpoint" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="virtualIPSource" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="virtualIPDestination" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="device" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="tlsMode" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TLS_VPN_TechnologyParameter", propOrder = {
    "peerPort",
    "l4Protocol",
    "localEndpoint",
    "remoteEndpoint",
    "virtualIPSource",
    "virtualIPDestination",
    "device",
    "tlsMode"
})
public class TLSVPNTechnologyParameter
    extends TechnologySpecificParameters
{

    protected String peerPort;
    @XmlElement(name = "L4Protocol")
    protected String l4Protocol;
    protected String localEndpoint;
    protected String remoteEndpoint;
    protected String virtualIPSource;
    protected String virtualIPDestination;
    protected String device;
    protected String tlsMode;

    /**
     * Gets the value of the peerPort property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPeerPort() {
        return peerPort;
    }

    /**
     * Sets the value of the peerPort property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPeerPort(String value) {
        this.peerPort = value;
    }

    /**
     * Gets the value of the l4Protocol property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getL4Protocol() {
        return l4Protocol;
    }

    /**
     * Sets the value of the l4Protocol property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setL4Protocol(String value) {
        this.l4Protocol = value;
    }

    /**
     * Gets the value of the localEndpoint property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLocalEndpoint() {
        return localEndpoint;
    }

    /**
     * Sets the value of the localEndpoint property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLocalEndpoint(String value) {
        this.localEndpoint = value;
    }

    /**
     * Gets the value of the remoteEndpoint property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRemoteEndpoint() {
        return remoteEndpoint;
    }

    /**
     * Sets the value of the remoteEndpoint property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRemoteEndpoint(String value) {
        this.remoteEndpoint = value;
    }

    /**
     * Gets the value of the virtualIPSource property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getVirtualIPSource() {
        return virtualIPSource;
    }

    /**
     * Sets the value of the virtualIPSource property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setVirtualIPSource(String value) {
        this.virtualIPSource = value;
    }

    /**
     * Gets the value of the virtualIPDestination property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getVirtualIPDestination() {
        return virtualIPDestination;
    }

    /**
     * Sets the value of the virtualIPDestination property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setVirtualIPDestination(String value) {
        this.virtualIPDestination = value;
    }

    /**
     * Gets the value of the device property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDevice() {
        return device;
    }

    /**
     * Sets the value of the device property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDevice(String value) {
        this.device = value;
    }

    /**
     * Gets the value of the tlsMode property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTlsMode() {
        return tlsMode;
    }

    /**
     * Sets the value of the tlsMode property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTlsMode(String value) {
        this.tlsMode = value;
    }

}
