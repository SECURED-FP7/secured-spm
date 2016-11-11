//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.02.29 at 10:28:31 AM CET 
//


package main.java.hspl_class;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for edge complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="edge">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="src_Service" type="{http://www.w3.org/2001/XMLSchema}IDREF"/>
 *         &lt;element name="dst_Service" type="{http://www.w3.org/2001/XMLSchema}IDREF"/>
 *         &lt;element name="networkFields" type="{http://www.example.org/Refinement_Schema}networkFields" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "edge", propOrder = {
    "srcService",
    "dstService",
    "networkFields"
})
public class Edge {

    @XmlElement(name = "src_Service", required = true)
    @XmlIDREF
    @XmlSchemaType(name = "IDREF")
    protected Object srcService;
    @XmlElement(name = "dst_Service", required = true)
    @XmlIDREF
    @XmlSchemaType(name = "IDREF")
    protected Object dstService;
    protected NetworkFields networkFields;

    /**
     * Gets the value of the srcService property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public Object getSrcService() {
        return srcService;
    }

    /**
     * Sets the value of the srcService property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setSrcService(Object value) {
        this.srcService = value;
    }

    /**
     * Gets the value of the dstService property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public Object getDstService() {
        return dstService;
    }

    /**
     * Sets the value of the dstService property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setDstService(Object value) {
        this.dstService = value;
    }

    /**
     * Gets the value of the networkFields property.
     * 
     * @return
     *     possible object is
     *     {@link NetworkFields }
     *     
     */
    public NetworkFields getNetworkFields() {
        return networkFields;
    }

    /**
     * Sets the value of the networkFields property.
     * 
     * @param value
     *     allowed object is
     *     {@link NetworkFields }
     *     
     */
    public void setNetworkFields(NetworkFields value) {
        this.networkFields = value;
    }

}