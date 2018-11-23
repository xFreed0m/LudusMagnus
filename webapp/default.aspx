<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="default.aspx.cs" Inherits="webapp._default" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Ludus Magnus</title>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
    <script>
        function getRdpFile() {
            var ipAddress = document.getElementById("IPAddress");
            var jumpboxAdmin = document.getElementById("User");
            var contents = [
                'full address:s:' + ipAddress.innerText,
                'audiomode:i:0',
                'disable wallpaper:i:0',
                'redirectprinters:i:0',
                'redirectcomports:i:0',
                'redirectsmartcards:i:0',
                'redirectclipboard:i:1',
                'redirectposdevices:i:0',
                'prompt for credentials:i:1',
                'negotiate security layer:i:0',
                'username:s:' + jumpboxAdmin.innerText
            ].join('\n');
            var blob = new Blob([contents], { type: 'text/csv' });
            var filename = 'JumpBox.rdp';
            if (window.navigator.msSaveOrOpenBlob) {
                window.navigator.msSaveBlob(blob, filename);
            }
            else {
                var elem = window.document.createElement('a');
                elem.href = window.URL.createObjectURL(blob);
                elem.download = filename;
                document.body.appendChild(elem);
                elem.click();
                document.body.removeChild(elem);
            }
        }
        function markPresent() {
            window.markDate = new Date();
            $(document).ready(function () {
                $("div.absent").toggleClass("present");
            });
            updateClock();
        }
        function updateClock() {
            var currDate = new Date();
            var diff = currDate - markDate;
            var t = document.getElementById("timeElapsed");
            if (t) { t.innerHTML = format(diff / 1000); }
            setTimeout(function () { updateClock() }, 1000);
        }
        function format(seconds) {
            var numhours = parseInt(Math.floor(((seconds % 31536000) % 86400) / 3600), 10);
            var numminutes = parseInt(Math.floor((((seconds % 31536000) % 86400) % 3600) / 60), 10);
            var numseconds = parseInt((((seconds % 31536000) % 86400) % 3600) % 60, 10);
            return ((numhours < 10) ? "0" + numhours : numhours)
                + ":" + ((numminutes < 10) ? "0" + numminutes : numminutes)
                + ":" + ((numseconds < 10) ? "0" + numseconds : numseconds);
        }
        markPresent();
    </script>
    <style>
        h1 {
            font-family: Calibri;
            font-size: 22px
        }

        table {
            font-family: Calibri;
            border: #1d1d1d 1px solid;
        }

        th {
            background-color: #1d1d1d;
            padding: 10px 16px;
            color: #ffffff;
        }
    </style>
</head>
<body>
    <form id="frmLudusMagnus" runat="server">
        <div>
            <% if (Session["step"] != null && Session["step"].ToString() == "1") { %>
            <table border="1">
                <tr>
                    <td>Please enter your name: </td>
                    <td>
                        <input name="name" id="name" type="text" runat="server" /></td>
                </tr>
                <tr>
                    <td colspan="2">
                        <input name="submit" type="submit" runat="server" />
                    </td>
                </tr>
            </table>
            <% } %>
            <% if (Session["step"] != null && Session["step"].ToString() == "2") { %>
            <table border="1">
                <tr>
                    <td colspan="2">Hello <%=Session["Name"].ToString() %>,</td>
                </tr>
                <tr>
                    <td>Your Jumpbox server IP is:</td>
                    <td><div id="IPAddress"><%=Session["IPAddress"].ToString() %></div></td>
                </tr>
                <tr>
                    <td>The UserName is:</td>
                    <td><div id="User"><%=Session["User"].ToString() %></div></td>
                </tr>
                <tr>
                    <td>The Password is:</td>
                    <td><%=Session["Password"].ToString() %></td>
                </tr>
                <tr>
                    <td>Start time (UTC):</td>
                    <td><%=Session["StartTime"].ToString() %></td>
                </tr>
                <tr>
                    <td>Time elapsed ***:</td>
                    <td><div id="timeElapsed"></div></td>
                </tr>
                <tr>
                    <td colspan="2">
                        <input id="DownloadRdpFile" type="button" onclick="getRdpFile();" value="Download the RDP file" />
                    </td>
                </tr>
                <tr>
                    <td colspan="2">Good luck!</td>
                </tr>
            </table>
            <br />
            <table border="1">
                <tr>
                    <th>Flag Number:</th>
                    <th>Flag Value:</th>
                </tr>
                <tr>
                    <td>0</td>
                    <td>Flag0: {<input name="flag0" id="flag0" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>1</td>
                    <td>Flag1: {<input name="flag1" id="flag1" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>2</td>
                    <td>Flag2: {<input name="flag2" id="flag2" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>3</td>
                    <td>Flag3: {<input name="flag3" id="flag3" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>4</td>
                    <td>Flag4: {<input name="flag4" id="flag4" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>5</td>
                    <td>Flag5: {<input name="flag5" id="flag5" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>6</td>
                    <td>Flag6: {<input name="flag6" id="flag6" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>7</td>
                    <td>Flag7: {<input name="flag7" id="flag7" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>8</td>
                    <td>Flag8: {<input name="flag8" id="flag8" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td>9</td>
                    <td>Flag9: {<input name="flag9" id="flag9" type="text" runat="server" />}</td>
                </tr>
                <tr>
                    <td colspan="2">
                        <input name="submit" type="submit" runat="server" />
                    </td>
                </tr>
            </table>
            <% } %>
        </div>
    </form>
</body>
</html>
