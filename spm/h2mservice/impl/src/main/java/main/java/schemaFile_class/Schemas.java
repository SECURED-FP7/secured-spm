//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: 2015.05.14 at 09:55:21 AM CEST
//


package main.java.schemaFile_class;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="refinement_Schema" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="MSPL_XML_Schema" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="configuration_Schema" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="matching_Schema" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="associationList_Schema" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "")
@XmlRootElement(name = "schemas")
public class Schemas {

    @XmlAttribute(name = "refinement_Schema")
    protected String refinementSchema;
    @XmlAttribute(name = "MSPL_XML_Schema")
    protected String msplxmlSchema;
    @XmlAttribute(name = "configuration_Schema")
    protected String configurationSchema;
    @XmlAttribute(name = "matching_Schema")
    protected String matchingSchema;
    @XmlAttribute(name = "associationList_Schema")
    protected String associationListSchema;

    /**
     * Gets the value of the refinementSchema property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getRefinementSchema() {
        return refinementSchema;
    }

    /**
     * Sets the value of the refinementSchema property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setRefinementSchema(String value) {
        this.refinementSchema = value;
    }

    /**
     * Gets the value of the msplxmlSchema property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getMSPLXMLSchema() {
        return msplxmlSchema;
    }

    /**
     * Sets the value of the msplxmlSchema property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setMSPLXMLSchema(String value) {
        this.msplxmlSchema = value;
    }

    /**
     * Gets the value of the configurationSchema property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getConfigurationSchema() {
        return configurationSchema;
    }

    /**
     * Sets the value of the configurationSchema property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setConfigurationSchema(String value) {
        this.configurationSchema = value;
    }

    /**
     * Gets the value of the matchingSchema property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getMatchingSchema() {
        return matchingSchema;
    }

    /**
     * Sets the value of the matchingSchema property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setMatchingSchema(String value) {
        this.matchingSchema = value;
    }

    /**
     * Gets the value of the associationListSchema property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getAssociationListSchema() {
        return associationListSchema;
    }

    /**
     * Sets the value of the associationListSchema property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setAssociationListSchema(String value) {
        this.associationListSchema = value;
    }

}