//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.20 at 05:38:59 PM CEST 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SafeNet complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SafeNet">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="SafeSurfprofanity">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="0"/>
 *             &lt;maxInclusive value="4"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="SafeSurfheterosexualthemes">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="0"/>
 *             &lt;maxInclusive value="4"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="SafeSurfhomosexualthemes">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="0"/>
 *             &lt;maxInclusive value="4"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="SafeSurfviolence">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="0"/>
 *             &lt;maxInclusive value="4"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="SafeSurfdruguse">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="0"/>
 *             &lt;maxInclusive value="4"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="SafeSurfotheradultthemes">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minInclusive value="0"/>
 *             &lt;maxInclusive value="4"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *       &lt;attribute name="SafeSurfgambling">
 *         &lt;simpleType>
 *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}int">
 *             &lt;minExclusive value="0"/>
 *             &lt;maxExclusive value="4"/>
 *           &lt;/restriction>
 *         &lt;/simpleType>
 *       &lt;/attribute>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SafeNet")
public class SafeNet {

    @XmlAttribute(name = "SafeSurfprofanity")
    protected Integer safeSurfprofanity;
    @XmlAttribute(name = "SafeSurfheterosexualthemes")
    protected Integer safeSurfheterosexualthemes;
    @XmlAttribute(name = "SafeSurfhomosexualthemes")
    protected Integer safeSurfhomosexualthemes;
    @XmlAttribute(name = "SafeSurfviolence")
    protected Integer safeSurfviolence;
    @XmlAttribute(name = "SafeSurfdruguse")
    protected Integer safeSurfdruguse;
    @XmlAttribute(name = "SafeSurfotheradultthemes")
    protected Integer safeSurfotheradultthemes;
    @XmlAttribute(name = "SafeSurfgambling")
    protected Integer safeSurfgambling;

    /**
     * Gets the value of the safeSurfprofanity property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSafeSurfprofanity() {
        return safeSurfprofanity;
    }

    /**
     * Sets the value of the safeSurfprofanity property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSafeSurfprofanity(Integer value) {
        this.safeSurfprofanity = value;
    }

    /**
     * Gets the value of the safeSurfheterosexualthemes property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSafeSurfheterosexualthemes() {
        return safeSurfheterosexualthemes;
    }

    /**
     * Sets the value of the safeSurfheterosexualthemes property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSafeSurfheterosexualthemes(Integer value) {
        this.safeSurfheterosexualthemes = value;
    }

    /**
     * Gets the value of the safeSurfhomosexualthemes property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSafeSurfhomosexualthemes() {
        return safeSurfhomosexualthemes;
    }

    /**
     * Sets the value of the safeSurfhomosexualthemes property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSafeSurfhomosexualthemes(Integer value) {
        this.safeSurfhomosexualthemes = value;
    }

    /**
     * Gets the value of the safeSurfviolence property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSafeSurfviolence() {
        return safeSurfviolence;
    }

    /**
     * Sets the value of the safeSurfviolence property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSafeSurfviolence(Integer value) {
        this.safeSurfviolence = value;
    }

    /**
     * Gets the value of the safeSurfdruguse property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSafeSurfdruguse() {
        return safeSurfdruguse;
    }

    /**
     * Sets the value of the safeSurfdruguse property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSafeSurfdruguse(Integer value) {
        this.safeSurfdruguse = value;
    }

    /**
     * Gets the value of the safeSurfotheradultthemes property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSafeSurfotheradultthemes() {
        return safeSurfotheradultthemes;
    }

    /**
     * Sets the value of the safeSurfotheradultthemes property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSafeSurfotheradultthemes(Integer value) {
        this.safeSurfotheradultthemes = value;
    }

    /**
     * Gets the value of the safeSurfgambling property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSafeSurfgambling() {
        return safeSurfgambling;
    }

    /**
     * Sets the value of the safeSurfgambling property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSafeSurfgambling(Integer value) {
        this.safeSurfgambling = value;
    }

}
