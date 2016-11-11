//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.11.25 at 11:07:59 AM CET 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for IPsecTechnologyParameter complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IPsecTechnologyParameter">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}TechnologySpecificParameters">
 *       &lt;sequence>
 *         &lt;element name="IPsecProtocol" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="isTunnel" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="localEndpoint" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="remoteEndpoint" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IPsecTechnologyParameter", propOrder = {
    "iPsecProtocol",
    "isTunnel",
    "localEndpoint",
    "remoteEndpoint"
})
public class IPsecTechnologyParameter
    extends TechnologySpecificParameters
{

    @XmlElement(name = "IPsecProtocol", required = true)
    protected String iPsecProtocol;
    protected boolean isTunnel;
    @XmlElement(required = true)
    protected String localEndpoint;
    @XmlElement(required = true)
    protected String remoteEndpoint;

    /**
     * Gets the value of the iPsecProtocol property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getIPsecProtocol() {
        return iPsecProtocol;
    }

    /**
     * Sets the value of the iPsecProtocol property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setIPsecProtocol(String value) {
        this.iPsecProtocol = value;
    }

    /**
     * Gets the value of the isTunnel property.
     * 
     */
    public boolean isIsTunnel() {
        return isTunnel;
    }

    /**
     * Sets the value of the isTunnel property.
     * 
     */
    public void setIsTunnel(boolean value) {
        this.isTunnel = value;
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

}
