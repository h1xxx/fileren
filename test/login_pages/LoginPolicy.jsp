



























































<!DOCTYPE HTML>
<html>
    <head>
        <meta http-equiv="REFRESH" content="1140">
                    
        



        <meta name="viewport" content="initial-scale=1.0,maximum-scale=1.0;"/>
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/>
        <meta http-equiv="Expires" content="Wed, 26 Feb 1997 08:21:57 GMT"/>
        <meta http-equiv="Pragma" content="no-cache"/>
        <link rel="apple-touch-icon" href="/apple-touch-icon-57x57.png" sizes="57x57" />
        <link rel="apple-touch-icon" href="/apple-touch-icon-72x72.png" sizes="72x72" />
        <link rel="apple-touch-icon" href="/apple-touch-icon-114x114.png" sizes="114x114" />
        <title>GoCSN</title>
        <link rel="stylesheet" type="text/css" href="/6.5.7.28/stylesheets/Default_loginWebOS.css?template=3"/>
        <!-- Future Optimization test for file instead of 404 -->
        <link rel="stylesheet" type="text/css" href="/6.5.7.28/stylesheets/loginWebOS.css?template=3"/>
        <style type="text/css">
            @import "/swAssets/dojo/dijit/themes/claro/claro.css";
        </style>
        <script type="text/javascript" src="/swAssets/6.5.7.28/dojo/dojo/dojo.js" djConfig="isDebug:true, parseOnLoad: true, debugAtAllCosts: false"></script>
        <script type="text/javascript" src="/6.5.7.28/login.js"></script> 
        <script type="text/javascript">

            dojo.require("dojo.parser");
            dojo.require("dijit.Dialog");


        </script>    
        <!--<script type="text/javascript" src="/js/cache_dojo.js"></script>   -->
        <script type="text/javascript">
            function launchOpenIDLogin(dest_url) {
                location.href = "/openid/openIDStart.jsp?openid_identifier=" + dest_url;
                return false;
            }
            function launchOpenIDConnectLogin(dest_url) {
                location.href = "/openid/openIDConnectStart.jsp?openid_identifier=" + dest_url;
                return false;
            }
            function launchOpenIDClaim() {
                location.href = "/pageWrapper.jsp?hk=pagewrapper.message.openidclaim&url=/openid/openIDClaim.jsp?";
            }
            
            //all this logic is to work around an android slate bug where input tabbing doesn't work when the inputs are covered by the keyboard
            var isAndroidSlate = false;
            if (isAndroidSlate ) {
                window.onresize = checkSize;
            }
            var zIndexCnt = 400;
            var baseClassName = "";
            function checkSize() {
                if (isAndroidSlate) {
                    if (document.getElementById("LoginBox").offsetHeight + 100 > document.body.clientHeight ) {
                        document.getElementById("LoginBox").className = "movedUp";
                    } else if (document.getElementById("LoginBox").offsetHeight + 100 < document.body.clientHeight ) {
                        document.getElementById("LoginBox").className = "";

                    } 
                }
            }
            
            document.addEventListener("DOMContentLoaded", function() {
                checkSize();
            });           
        </script>
    </head>
    <body class="loginPage claro">
        


<table id="LoginTable" border="0" cellspacing="0">
    <tr id="loginHeaderRow">
        <td class="loginHeader">
            <div class="loginFormLogo"></div>
        </td>
    </tr>
    <tr id="BackgroundDisplayHelper">
        <td class="loginBlockCell"> 
            <div class="loginTitleBlock"><span>GoCSN</span></div>
                <div class="loginLinksBlock">
                    <div class="blankLoginBox">
                        <h1>Additional Links</h1>
                        







        <table class="loginForm-info-table">
            <tr>
                <td>
                    
                    <a href="/apps/selfService/resetPassword.jsp" style="text-decoration: none">
                        <div class="loginInformation-icon resetPasswordIcon"><span class="loginInformation-label">Reset Password<span class="loginForm-colon">:</span></span><br/>
                            <span class="loginInformation-link">Click here if you need to reset or have forgotten your CSN Active Directory network password (For MyCSN, Canvas, GoCSN, and CSN Email)</span>
                        </div>
                    </a>
                    
                    <a href="/apps/systemCheck/systemCheck.jsp" style="text-decoration: none" target="_blank" onclick="if (launchSystemCheck) return launchSystemCheck()">
                        <div class="loginInformation-icon sysCheckIcon"><span class="loginInformation-label">System Check<span class="loginForm-colon">:</span></span><br/>
                            <span class="loginInformation-link">Click here to run a system check</span>
                        </div>
                    </a>
                    
                    
                    <a href="/additionalInformation.jsp" style="text-decoration: none" target="_blank">
                        <div class="loginInformation-icon addtInfoIcon"><span class="loginInformation-label">Account Validation<span class="loginForm-colon">:</span></span><br/>
                            <span class="loginInformation-link">Click here if you haven't ever set up your CSN Login Password</span>
                        </div>
                    </a>
                    
                </td>
            </tr>
        </table>


                        
                            
                        














         


                    </div>
                </div>
                <div class="loginFormBlock">
                    <div id="LoginBox">
                        <div id="LoadingIndicator"><div id="LoadingIcon"></div></div>
                        <h1>Login</h1>
                        <div id="samlMessage"></div>
                         
                            
                        


















































        <div id="controlElement" style="height:1px;width: 1px;"></div>
        
        <script src="https://ssl.gstatic.com/accounts/chrome/users-1.0.js"></script>
        <script src="/6.5.7.28/js/cookie.js"></script>
        <script>
            document.addEventListener("DOMContentLoaded", function() {
                try {
                    google.principal.initialize(function(keyTypes) {
                        // the only key type we handle is KEY_TYPE_PASSWORD_PLAIN. If it is not present, skip and log.
                        // KEY_TYPE_PASSWORD_PLAIN is the only password type as of 07/17/2017
                        if(keyTypes.indexOf("KEY_TYPE_PASSWORD_PLAIN") > -1) {
                            Cookies.set("gaia_saml_api_enabled", "true");
                            // if we support more types later, set a cookie to show what types are available. 
                            //Cookies.set("key_types", "KEY_TYPE_PASSWORD_PLAIN");  
                        } else {
                            var msg = "Invalid key types: " + keyTypes;
                            if(document.getElementById("samlMessage")) {
                                document.getElementById("samlMessage").innerHTML = msg;
                            } else {
                                console.log(msg);
                            }
                        }
                    });
                }
                catch (err) {
                    var msg = "1) " + err;
                    if(document.getElementById("samlMessage")) {
                        document.getElementById("samlMessage").innerHTML = msg;
                    } else {
                        console.error(msg);
                    }
                }
            });            
        </script>        
        <script type="text/javascript">
            //Writes USB Applet/ActiveX to controlElement DIV after Dojo (if used) has reloaded page
            function writeControl(id) {
            
            }

            //Call back from USBApplet after applet is loaded and has completed probing for USB devices
            function displayResults() {
            }

            if (window.dojo) {
                writeControl('BackgroundDisplayHelper');
            }
            else {
                writeControl('controlElement');
            }

            var allowCRC = false;

            function checkEnterOnSubmit(event) {
                var e = event ? event : window.event;
                if (e == undefined)
                    return;
                var pK = e.which ? e.which : e.keyCode;
                if (pK == 13) {
                    if (document.getElementsByClassName) {
                        var inputs = document.getElementsByClassName("loginForm-text-input");
                        var isTextInputFilled = false;
                        var isPwInputFilled = false;
                        for (var a = 0; a < inputs.length; a++) {
                            if (inputs[a].type == "text" && inputs[a].value.length > 0) {
                                isTextInputFilled = true;
                            } else if (inputs[a].type == "password" && inputs[a].value.length > 0) {
                                isPwInputFilled = true;
                            }
                        }
                    } else { //cant' check this in template 1 for IE
                        isTextInputFilled = true;
                        isPwInputFilled = true;
                    }
                    if (isTextInputFilled && isPwInputFilled) {
                        setLoading();
                    }
                }
            }

            function setLoading() {
                if (isSample)
                    return;
                if (window.dijit && dijit.byId) {
                    var dojo1loginBtn = dijit.byId("LoginButton");
                    if (dojo1loginBtn) {
                        dojo1loginBtn.attr("iconClass", "loadingIcon");
                        dojo1loginBtn.attr("disabled", "true");
                    }
                } else {
                    var loginBtn = document.getElementById("LoginButton");
                    if (loginBtn) {
                        loginBtn.className = "Disabled WebOSButton";
                    }
                }

                var loadingIndicator = document.getElementById("LoadingIndicator");
                if (loadingIndicator) {
                    loadingIndicator.style.display = "block";
                    var loadingIcon = document.getElementById("LoadingIcon");
                    loadingIcon.className = "loading";
                }
                prepareFormSubmit();
            }

            // function to determine that we aren't dealing with iOS devices
            function notiOS() {
                var ua = navigator.userAgent.toLowerCase();
                return ua.indexOf("ipad") == -1 && ua.indexOf("iphone") == -1 && ua.indexOf("ipod") == -1;
            }

            var doLoadingIcon = true;
            var isSample = false;
            var isLoggingIn = false;
            function prepareFormSubmit() {
                if (isLoggingIn)
                    return;

                isLoggingIn = true;
                /*if (window.console && window.console.debug)console.debug("otpStatus", otpStatus);
                 if (allowCRC && otpRequired && !shown503) {
                 if (otpStatus == 0) {
                 otpStatus = 3;
                 queryOTP();
                 return false;
                 }
                 }*/

                try {
                    window.status = 'Please wait while we access your account...';
                    var usbControl = document.getElementById('USBControl');
                    var usbSelect = document.getElementById('wnHardwareID');
                
                    if (usbControl != null && usbSelect != null && notiOS()) {
                        if (navigator.userAgent.toLowerCase().indexOf("msie") != -1 && false) {
                            for (var i = 0; i < usbControl.GetDeviceCount(); i++) {
                                usbSelect.options[i] = new Option(usbControl.DeviceString(i), usbControl.DeviceString(i), true, true);
                            }
                        }
                        else {
                            var keys = eval('(' + usbControl.getKeys() + ')');
                            for (var i = 0; i < keys.length; i++) {
                                usbSelect.options[i] = new Option(keys[i].serial, keys[i].serial, true, true);
                            }
                        }
                    }
                }
                catch (err) {
                    console.error(err);
                }
                
                try {
                    var gaiaSamlApiEnabled = false;
                    
                    // check for Cookies. Some custom login pages will not it. 
                    // use == so that we can compare on null and undefined
                    if(Cookies == null) {
                        gaiaSamlApiEnabled = Cookies.get("gaia_saml_api_enabled");
                    }
                    
                    if( gaiaSamlApiEnabled ) {
                        var relayState = "";
                    
                        var details = {
                            token: relayState,
                            user: "", /* we don't know the user's email address, so default to empty string */
                            passwordBytes: document.forms[0].elements.namedItem("[password]").value,
                            keyType: "KEY_TYPE_PASSWORD_PLAIN"
                        };

                        google.principal.add(details, function() {
                            document.forms[0].submit();
                        });
                    } else {
                        setTimeout("document.forms[0].submit();", 50); //added a timeout so the loading icon will start spinning in Chrome
                    }
                }
                catch (err) {
                    if(document.getElementById("samlMessage")) {
                        document.getElementById("samlMessage").innerHTML = "2) " + err;
                    } else {
                        console.error(msg);
                    } 
                }
            }

            var hardwareProperties = [
                ["Core", "TotalInstalledMemory", "installedMemory"]
            ];
            
            function getHardwareInfo() {
                intel.webapi.context.get("Device", successCB, errorCB);
            }

            function successCB(infoObject) {
                infoObject = getValue(infoObject);
                buildHardwareString({'TotalInstalledMemory': Math.round(infoObject.totalInstalledMemory / 1024 / 1024)});
            }

            function errorCB(arg) {
                if (window.console && window.console.debug)
                    console.debug("error code", arg.code); //error code will be 2 if scanner is not present
                //if (otpStatus == 3) { //otp query began after user submitted the form, so submit now that the query has completed, even though it failed
                //    otpStatus = 2;
                document.forms[0].submit();
                //}

            }
            var hardwareJSON = "{";
            var hardwareInfoRetrievedCnt = 0;
            function buildHardwareString(infoObject) {
                for (var pName in infoObject) {

                    if (hardwareJSON.length > 1) {
                        hardwareJSON += ",";
                    }
                    var value = infoObject[pName];
                    hardwareJSON += "'" + getClientHardwareProperty(pName) + "':" + value;

                }
                hardwareInfoRetrievedCnt++;
                if (hardwareInfoRetrievedCnt == hardwareProperties.length) {
                    hardwareJSON += "}";
                    document.forms[0].elements['[Client.Hardware]'].value = hardwareJSON;
                }
            }

            function getClientHardwareProperty(intelProperty) {
                for (var n = 0; n < hardwareProperties.length; n++) {
                    if (hardwareProperties[n][1] == intelProperty) {
                        return hardwareProperties[n][2];
                    }
                }
                return intelProperty;
            }

            if (window.dojo) {
                dojo.addOnLoad(init);
            } else {
                window.onload = init;
            }


            var otpRequired = true;
            var otpTries = 0;
            var waitingForOTP = false;
            // -3 = not checked if scanner is present
            // -2 = checking if scanner is present
            // -1 = user has submitted the form while check is in progress
            // 0 = scanner status is available, but not queried OTP
            // 1 = queried
            // 2 = recieved query
            // 3 = submitting login form after otpReturns
            var otpStatus = 0; //we are no longer checking for scanner status
            var scannerPresent = false;

            var claimOpenID = false;
            function init() {
                if (allowCRC) {
                    setTimeout("checkHardwareService();", 500);
                }
                if (claimOpenID) {
                    launchOpenIDClaim();
                }
                getScreenSize();
                //otpStatus = -2;
                //setTimeout("ScannerCheckTimeout();", 5000); //if for whatever reason the scanner check does not notify us, then we we need to assume the device is not present
            }

            function getScreenSize() {
                var w = window.innerWidth;
                var h = window.innerHeight;
                document.getElementById("ViewportSize").value = w + "x" + h;
            }

            function serviceExists() {
                getHardwareInfo();
            }

            var shown503 = false;
            function serivceError(error) {
                if (error.Code == 401) {
                    otpStatus = 0;
                }
                if (shown503)
                    return;
                shown503 = error.Code == 503;
                if (window.console && window.console.debug)
                    console.debug('An Error occurred\nError Code:' + error.Code + "\nError Message: " + error.Message);
            }

            function getScannerStatus(infoObject) {
                if (window.console && window.console.debug)
                    console.debug("getScannerStatus()", infoObject);
                otpStatus = 0;
                scannerPresent = infoObject.IsFPScanneravailable == "True";
                if (scannerPresent) {
                    var display = false ? "block" : "table-row";
                    document.getElementById("OTPRow").style.display = display;
                    document.getElementById("OTPRow2").style.display = display;
                }
            }

            function ScannerCheckTimeout() {
                if (otpStatus == -1) { //user has submitted form and the scanner check never returned, probably due to a 500 error
                    otpStatus = 0;
                    scannerPresent = false;
                    document.forms[0].submit();
                    if (window.console && window.console.debug)
                        console.debug("Error: Unable to determine if scanner is present");
                }
            }

            function queryOTP() {
                //if (otpStatus != 3)
                //    otpStatus = 1;
                //intel.webapi.context.OTPRequest(getOTPValue, serviceError);
                intel.OTP.getPassword(getOTPValue, errorCB);
            }

            function getOTPValue(infoObject) {
                //console.debug("infoObject", infoObject);
                if (infoObject && infoObject.response && infoObject.response.authenticated) {
                    //document.forms[0].elements['[RADIUS.user]'].value = infoObject.CredentialId;
                    document.forms[0].elements['[RADIUS.password]'].value = infoObject.response.otp;
                }
                if (otpStatus == 3) { //otp query began after user submitted the form, so submit now that we have the value
                    otpStatus = 2;
                    document.forms[0].submit();
                } else {
                    otpStatus = 2;
                }

            }

            function checkOTPRetrieval() {
                //  console.debug("checkOTPRetrieval",retrievedOTP );
                if (retrievedOTP) {
                    document.forms[0].submit();
                } else if (otpTries < 15) {
                    otpTries++;
                    setTimeout("checkOTPRetrieval()", 500);
                } else {
                    document.getElementById("LoginButton").value = "Log In";
                    alert("We were unable to detect your fingerprint scan, which is required for you to log in.  Please contact support."); //FIXME - localize
                }
            }

            function checkOTP() {
                console.debug("checkOTP");
                if (otpStatus == 0) {
                    queryOTP();
                }
            }

            function focusElement() {
                gFocusElement.focus();
            }

            function enableAndFocus(element) {
                gFocusElement = element;
                element.readOnly = false;
                setTimeout("focusElement()", 1000);
            }
        </script>
            <form id="loginForm" name="loginForm" method="post" action="/WebNetworkAuth/">
                <input type="hidden" name="csrfToken" value="SIYXE8YTOv4doWBWMvou"/>
                
                <input type="hidden" name="[Client.Hardware]" value=""/>
                <input type="hidden" id="ViewportSize" name='[User.ViewportSize]'/>
                <div id='errorMessage'></div>
                <table class="loginForm-main-table" >
                    
                    
                    
                        
                            

                            

                            
                                
                                    
                                
                                
                                

                                <tr>
                                    <td class="loginForm-label-cell">
                                        <div class="loginForm-label-text">Username<span class="loginForm-colon">:</span></div>
                                        
                                        
                                        <div class="loginForm-input-container">
                                            <div class="loginForm-text-input-icon Username"></div>
                                            <input class="loginForm-text-input"  type='text' invalidplaceholder="Username" name='cn'  onfocus="try {
                                                        if (focusStyle)
                                                            focusStyle(this)
                                                    } catch (err) {
                                                    }" onblur="try {
                                                                if (blurStyle)
                                                                    blurStyle(this)
                                                            } catch (err) {
                                                            }" onkeyup="return checkEnterOnSubmit(event)" autocapitalize="off" autocorrect="off" autocomplete="off" tabindex="1"/>
                                        </div>
                                    </td>
                                </tr>

                            
                        
                    
                        
                            

                            

                            
                                
                                
                                    
                                
                                

                                <tr>
                                    <td class="loginForm-label-cell">
                                        <div class="loginForm-label-text">Password<span class="loginForm-colon">:</span></div>
                                        
                                        
                                        <div class="loginForm-input-container">
                                            <div class="loginForm-text-input-icon Password"></div>
                                            <input class="loginForm-text-input"  type='password' invalidplaceholder="Password" name='[password]'  onfocus="try {
                                                        if (focusStyle)
                                                            focusStyle(this)
                                                    } catch (err) {
                                                    }" onblur="try {
                                                                if (blurStyle)
                                                                    blurStyle(this)
                                                            } catch (err) {
                                                            }" onkeyup="return checkEnterOnSubmit(event)" autocapitalize="off" autocorrect="off" autocomplete="off" tabindex="2"/>
                                        </div>
                                    </td>
                                </tr>

                            
                        
                    
                    
                    
                    
                    <tr>
                        <td class="loginForm-button-cell" align="right" colspan="2">
                            
                            <input id="LoginButton" class="WebOSButton" type="button" onclick="setLoading()" alt="Login Button" value="Log In" name="I1" onmouseover="try {
                                        if (toggleHover)
                                            toggleHover(this)
                                    } catch (err) {
                                    }" onmouseout="try {
                                                if (toggleHover)
                                                    toggleHover(this)
                                            } catch (err) {
                                            }" />
                            
                        </td>
                    </tr>
                </table>
            </form>


                    </div>
                </div> 
        
        </td>
    </tr>
    <tr id="loginFooterRow">
        <td class="loginFooter" >
            <div id="loginFooterGraphic">

            </div>
           
        <img src="/swDashboard/images/icons/stock/iToolbar 2/16x16/exclamation.png" title="ext-relay-CYAPWKS02" style="float:left">
        
        <span class="loginCopyRightText">
            <script type="text/javascript">
                document.writeln( "&copy; Stoneware, Inc. 1999-" + new Date().getFullYear() );
            </script>
        </span>
        </td>
    </tr>
</table>         
    </body>
</html>
