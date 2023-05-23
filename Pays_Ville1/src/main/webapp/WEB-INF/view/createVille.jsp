<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
    <link rel="stylesheet" type="text/css" href="webjars/bootstrap/4.3.1/css/bootstrap.min.css" />
    <c:url value="/css/main.css" var="jstlCss" />
    <link href="${jstlCss}" rel="stylesheet" />
    <script type="text/javascript" src="webjars/bootstrap/4.3.1/js/bootstrap.min.js">   </script>  
    <head>
        <meta  http-equiv="Content-Type" content="text/html; charset="ISO-8859-1">
        <title>Creer une  Ville</title>
    </head>
    <body>
            <div class="container mt-5" >
            <div class="card-body">
                <form action="saveVille" method="post">
                    <div class="form-group">
                        <label class="control-label">Nom Ville :</label>
                        <input type="text" name="nomVille" class="form-control"/>
                    </div>

                    <div class="form-group">
                        <label class="control-label">Numero Ville :</label>
                        <input type="text" name="numVille" class="form-control"/>
                    </div>

                    <div class="form-group">
                        <label class="control-label"> Code Postal :</label>
                        <input type="text" name="codePostal" class="form-control"/>
                    </div>

                    <div class="form-group">
                        <label class="control-label">EstCapitale :</label>
                        <input type="text" name="estCapitale" class="form-control"/>
                    </div>
                    
                
                    <div class="form-group">
                        <label class="control-label">Population :</label>
                        <input type="text" name="populationt" class="form-control"/>
                    </div>
                    
                    <div class="form-group">
                            <label class="control-label">Superficie :</label>
                            <input type="text" name="superficie" class="form-control"/>
                    </div>

                    <div class="form-group">
                        <label class="control-label">date creation :</label>
                        <input type="date" name="date" class="form-control"/>
                    </div>

                    <div>
                        <button type="submit" class="btn btn-primary">Ajouter</button>
                    </div>

                    
                </form>
            </div>
            ${msg}
            <br/>
            <br/>
            <a href="ListeVilles">Liste Villes</a>
            </div>
    </body>
</html>