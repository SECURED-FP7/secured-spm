//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.20 at 05:38:59 PM CEST 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for Pics complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="Pics">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="ICRA" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}ICRA"/>
 *         &lt;element name="RSAC" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}RSAC"/>
 *         &lt;element name="evaluWEB">
 *           &lt;simpleType>
 *             &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *               &lt;minInclusive value="0"/>
 *               &lt;maxInclusive value="2"/>
 *             &lt;/restriction>
 *           &lt;/simpleType>
 *         &lt;/element>
 *         &lt;element name="CyberNOTsex">
 *           &lt;simpleType>
 *             &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *               &lt;minInclusive value="0"/>
 *               &lt;maxInclusive value="8"/>
 *             &lt;/restriction>
 *           &lt;/simpleType>
 *         &lt;/element>
 *         &lt;element name="Weburbia">
 *           &lt;simpleType>
 *             &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *               &lt;minInclusive value="0"/>
 *               &lt;maxInclusive value="2"/>
 *             &lt;/restriction>
 *           &lt;/simpleType>
 *         &lt;/element>
 *         &lt;element name="Vancouver" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}Vancouver"/>
 *         &lt;element name="SafeNet" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}SafeNet"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Pics", propOrder = {
    "icra",
    "rsac",
    "evaluWEB",
    "cyberNOTsex",
    "weburbia",
    "vancouver",
    "safeNet"
})
public class Pics {

    @XmlElement(name = "ICRA", required = true)
    protected ICRA icra;
    @XmlElement(name = "RSAC", required = true)
    protected RSAC rsac;
    protected int evaluWEB;
    @XmlElement(name = "CyberNOTsex")
    protected int cyberNOTsex;
    @XmlElement(name = "Weburbia")
    protected int weburbia;
    @XmlElement(name = "Vancouver", required = true)
    protected Vancouver vancouver;
    @XmlElement(name = "SafeNet", required = true)
    protected SafeNet safeNet;

    /**
     * Gets the value of the icra property.
     * 
     * @return
     *     possible object is
     *     {@link ICRA }
     *     
     */
    public ICRA getICRA() {
        return icra;
    }

    /**
     * Sets the value of the icra property.
     * 
     * @param value
     *     allowed object is
     *     {@link ICRA }
     *     
     */
    public void setICRA(ICRA value) {
        this.icra = value;
    }

    /**
     * Gets the value of the rsac property.
     * 
     * @return
     *     possible object is
     *     {@link RSAC }
     *     
     */
    public RSAC getRSAC() {
        return rsac;
    }

    /**
     * Sets the value of the rsac property.
     * 
     * @param value
     *     allowed object is
     *     {@link RSAC }
     *     
     */
    public void setRSAC(RSAC value) {
        this.rsac = value;
    }

    /**
     * Gets the value of the evaluWEB property.
     * 
     */
    public int getEvaluWEB() {
        return evaluWEB;
    }

    /**
     * Sets the value of the evaluWEB property.
     * 
     */
    public void setEvaluWEB(int value) {
        this.evaluWEB = value;
    }

    /**
     * Gets the value of the cyberNOTsex property.
     * 
     */
    public int getCyberNOTsex() {
        return cyberNOTsex;
    }

    /**
     * Sets the value of the cyberNOTsex property.
     * 
     */
    public void setCyberNOTsex(int value) {
        this.cyberNOTsex = value;
    }

    /**
     * Gets the value of the weburbia property.
     * 
     */
    public int getWeburbia() {
        return weburbia;
    }

    /**
     * Sets the value of the weburbia property.
     * 
     */
    public void setWeburbia(int value) {
        this.weburbia = value;
    }

    /**
     * Gets the value of the vancouver property.
     * 
     * @return
     *     possible object is
     *     {@link Vancouver }
     *     
     */
    public Vancouver getVancouver() {
        return vancouver;
    }

    /**
     * Sets the value of the vancouver property.
     * 
     * @param value
     *     allowed object is
     *     {@link Vancouver }
     *     
     */
    public void setVancouver(Vancouver value) {
        this.vancouver = value;
    }

    /**
     * Gets the value of the safeNet property.
     * 
     * @return
     *     possible object is
     *     {@link SafeNet }
     *     
     */
    public SafeNet getSafeNet() {
        return safeNet;
    }

    /**
     * Sets the value of the safeNet property.
     * 
     * @param value
     *     allowed object is
     *     {@link SafeNet }
     *     
     */
    public void setSafeNet(SafeNet value) {
        this.safeNet = value;
    }

}
