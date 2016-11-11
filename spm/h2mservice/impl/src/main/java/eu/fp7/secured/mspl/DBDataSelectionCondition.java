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
 * <p>Java class for DBDataSelectionCondition complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DBDataSelectionCondition">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}DataSelectionCondition">
 *       &lt;sequence>
 *         &lt;element name="tableName" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="sqlQuery" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="viewName" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DBDataSelectionCondition", propOrder = {
    "tableName",
    "sqlQuery",
    "viewName"
})
public class DBDataSelectionCondition
    extends DataSelectionCondition
{

    @XmlElement(required = true)
    protected String tableName;
    @XmlElement(required = true)
    protected String sqlQuery;
    @XmlElement(required = true)
    protected String viewName;

    /**
     * Gets the value of the tableName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTableName() {
        return tableName;
    }

    /**
     * Sets the value of the tableName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTableName(String value) {
        this.tableName = value;
    }

    /**
     * Gets the value of the sqlQuery property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSqlQuery() {
        return sqlQuery;
    }

    /**
     * Sets the value of the sqlQuery property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSqlQuery(String value) {
        this.sqlQuery = value;
    }

    /**
     * Gets the value of the viewName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getViewName() {
        return viewName;
    }

    /**
     * Sets the value of the viewName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setViewName(String value) {
        this.viewName = value;
    }

}
