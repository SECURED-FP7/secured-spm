//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.02.29 at 12:19:02 PM CET 
//


package eu.fp7.secured.xml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for solution complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="solution">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="psaList" type="{http://www.example.org/Refinement_Schema}PSA_list"/>
 *       &lt;/sequence>
 *       &lt;attribute name="cost" type="{http://www.w3.org/2001/XMLSchema}double" />
 *       &lt;attribute name="latency" type="{http://www.w3.org/2001/XMLSchema}double" />
 *       &lt;attribute name="rating" type="{http://www.w3.org/2001/XMLSchema}double" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "solution", propOrder = {
    "psaList"
})
public class Solution {

    @XmlElement(required = true)
    protected PSAList psaList;
    @XmlAttribute
    protected Double cost;
    @XmlAttribute
    protected Double latency;
    @XmlAttribute
    protected Double rating;

    /**
     * Gets the value of the psaList property.
     * 
     * @return
     *     possible object is
     *     {@link PSAList }
     *     
     */
    public PSAList getPsaList() {
        return psaList;
    }

    /**
     * Sets the value of the psaList property.
     * 
     * @param value
     *     allowed object is
     *     {@link PSAList }
     *     
     */
    public void setPsaList(PSAList value) {
        this.psaList = value;
    }

    /**
     * Gets the value of the cost property.
     * 
     * @return
     *     possible object is
     *     {@link Double }
     *     
     */
    public Double getCost() {
        return cost;
    }

    /**
     * Sets the value of the cost property.
     * 
     * @param value
     *     allowed object is
     *     {@link Double }
     *     
     */
    public void setCost(Double value) {
        this.cost = value;
    }

    /**
     * Gets the value of the latency property.
     * 
     * @return
     *     possible object is
     *     {@link Double }
     *     
     */
    public Double getLatency() {
        return latency;
    }

    /**
     * Sets the value of the latency property.
     * 
     * @param value
     *     allowed object is
     *     {@link Double }
     *     
     */
    public void setLatency(Double value) {
        this.latency = value;
    }

    /**
     * Gets the value of the rating property.
     * 
     * @return
     *     possible object is
     *     {@link Double }
     *     
     */
    public Double getRating() {
        return rating;
    }

    /**
     * Sets the value of the rating property.
     * 
     * @param value
     *     allowed object is
     *     {@link Double }
     *     
     */
    public void setRating(Double value) {
        this.rating = value;
    }

}
