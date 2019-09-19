import org.primeframework.jwt.domain.JWT
import java.time.ZoneOffset
import java.time.ZonedDateTime
import org.primeframework.jwt.rsa.RSASigner
import com.github.kittinunf.fuel.*
import com.github.kittinunf.fuel.core.FuelManager
import com.github.kittinunf.result.*
import java.net.URLEncoder
import com.google.gson.*
import org.apache.commons.csv.CSVFormat
import org.apache.commons.csv.CSVParser
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

fun main(args: Array<String>) {
    if (!File(args[0] + "/configV2.json").exists()) {
        println("${args[0]}/configV2.json not found.  Aborting.")
        return
    }
    val jsonConfigText = File(args[0] + "/configV2.json").readText()
    val gsonParser = GsonBuilder().setPrettyPrinting().create()
    var configParams = mutableMapOf<String, String>()
    configParams = gsonParser.fromJson(jsonConfigText, configParams.javaClass)
    val fileDateFormat = "MMddyyyy"
    val fdFormatter = SimpleDateFormat(fileDateFormat)
    val mappedAccounts = mutableMapOf<Date, File>()
    val mappedGroups = mutableMapOf<Date, File>()
    val accounts = mutableMapOf<String, MutableMap<String, Any>>()
    val groups = mutableMapOf<String, MutableMap<String, Any>>()
    val fieldsWithSemicolons = arrayListOf("REPORT RECIPIENT NAMES", "REPORT RECIPIENT EMAILS"
            , "MARKETING SITE CONTACT NAMES", "MARKETING SITE CONTACT EMAILS")
    // Create patterns to match for valid filenames
    // https://txt2re.com/index-java.php3

    val re2 = "(_)"    // Any Single Character 1
    val re3 = "((?:[0]?[1-9]|[1][012])(?:(?:[0-2]?\\d{1})|(?:[3][01]{1}))(?:(?:[1]{1}\\d{1}\\d{1}\\d{1})|(?:[2]{1}\\d{3})))(?![\\d])"    // MMDDYYYY 1
    val re4 = "(\\.)"    // Any Single Character 2
    val re5 = "((?:[a-z][a-z]+))"    // Word 2
    val re6 = "(\\.)"    // Any Single Character 3
    val re7 = "(csv)"    // Word 3
    val employerRegex = "(EMPLOYERGROUPS)" + re2 + re3 + re6 + re7
    val planRegex = "(PLANDESIGN)" + re2 + re3 + re4 + re5 + re6 + re7
    val employerPattern = Regex(employerRegex)
    val planPattern = Regex(planRegex)

    // Sift out the files we can use
    File(args[0]).walkTopDown().maxDepth(1).sorted().forEach {
        if (it.name.startsWith("EMPLOYERGROUPS") || it.name.startsWith("PLANDESIGN"))
            if (planPattern.matches(it.name) || employerPattern.matches(it.name)) {
                var dateText = it.name.substringAfter('_').subSequence(0, 8)
                val fileDate = fdFormatter.parse(dateText.toString())

                if (it.name.startsWith("EMPLOYERGROUPS")) {
                    mappedAccounts.put(fileDate, it)
                } else if (it.name.startsWith("PLANDESIGN")) {
                    mappedGroups.put(fileDate, it)
                }
            }

    }

    // Now lets bring together the accounts and contacts before sending
    // Light error-checking
    // First parse accounts
    // NOTE: We are using UMR GROUP # as a grouping tool pre-etl.  OrgId and LegacyGroupId will be used within parser

    for ((_, tmpAcct) in mappedAccounts.toSortedMap()) {
        val tmpCsv = CSVParser(tmpAcct.reader(), CSVFormat.EXCEL.withHeader())
        for (tmpRec in tmpCsv.records) {
            val tmpAcctMap = mutableMapOf<String, Any>()
            for (tmpHdr in tmpCsv.headerMap) {
                val tmpKey = tmpHdr.key.trim().toUpperCase()
                var tmpVal = tmpRec[tmpHdr.key].trim()

                if (fieldsWithSemicolons.contains(tmpKey)) {
                    if (!tmpVal.isNullOrBlank()) {
                        tmpVal = tmpVal.trim().replace(',', ';').replace(':', ';')
                        val tmpItems = tmpVal.split(';')
                        var tmpItemString = ""
                        for (tmpItem in tmpItems) {
                            if (!tmpItem.isNullOrBlank())
                                tmpItemString += ";${tmpItem.trim()}"
                        }
                        tmpVal = tmpItemString.substring(1)
                    }
                    tmpAcctMap.put(tmpKey, tmpVal)
                } else
                    tmpAcctMap.put(tmpKey, tmpVal)
            }
            var tmpId = if (tmpAcctMap["UMR GROUP #"] == null) "EMPTY" else tmpAcctMap["UMR GROUP #"].toString()
            accounts.put(tmpId, tmpAcctMap)
        }
    }
    // Parse groups
    for ((_, tmpGrp) in mappedGroups.toSortedMap()) {
        val tmpCsv = CSVParser(tmpGrp.reader(), CSVFormat.EXCEL.withHeader())
        for (tmpRec in tmpCsv.records) {
            val tmpGrpMap = mutableMapOf<String, Any>()
            for (tmpHdr in tmpCsv.headerMap) {
                tmpGrpMap.put(tmpHdr.key.trim().toUpperCase(), tmpRec[tmpHdr.key].trim())
            }
            var tmpId = if (tmpGrpMap["UMR_GROUP__"] == null) "EMPTY" else tmpGrpMap["UMR_GROUP__"].toString()
            var tmpLgi = tmpGrpMap["LEGACY_GROUP_ID"]
            groups.put("$tmpId::$tmpLgi", tmpGrpMap)
        }

    }

    val outgoingBatch = mutableListOf<EtlInfo>()
    // Rewrite using groups as the driver because it will always be more groups than accounts
    for (tmpKey in groups.keys) {
        // must split group key to find matching account
        var groupKeyParts = tmpKey.split("::")
        var baseKey = groupKeyParts[0]
        //var tmpAcctInfo: MutableMap<String, Any>? = accounts[baseKey] ?: continue
        var tmpAcctInfo = accounts[baseKey]
        var tmpGroupInfo = groups[tmpKey]
        val groupKey = tmpGroupInfo?.get("LEGACY_GROUP_ID")
        if (groupKey != null)
            outgoingBatch.add(EtlInfo(groupKey as String, tmpAcctInfo!!, tmpGroupInfo!!))
    }
    val jsonText = gsonParser.toJson(outgoingBatch)
    File("${args[0]}/umrBatch.json").writeText(jsonText)

    // Send defaults if they exist

    var tmpDefMap = if (File("${args[0]}/${configParams["defaults_file"]}").exists()) {
        val tmpDefs = File("${args[0]}/${configParams["defaults_file"]}")
        val tmpCsv = CSVParser(tmpDefs.reader(), CSVFormat.EXCEL.withHeader())
        val tmpDefMap = mutableMapOf<String, Any>()
        for (tmpRec in tmpCsv.records) {

            for (tmpHdr in tmpCsv.headerMap) {
                val tmpKey = tmpHdr.key.trim().toUpperCase()
                var tmpVal = tmpRec[tmpHdr.key].trim()

                tmpDefMap.put(tmpKey, tmpVal)
            }
        }
        tmpDefMap.toMap()
    } else
        null


    val instanceInfo = authenticate(configParams)

    postData(instanceInfo, outgoingBatch, tmpDefMap)
}

private fun postData(instanceInfo: SfdcResponse?, outgoing: List<EtlInfo>, defaults: Map<String, Any>?) {
    val websvc = "${instanceInfo?.instance_url}/services/apexrest/UmrUpload/v2"

    FuelManager.instance.baseHeaders = mapOf("Content-Type" to "application/json; charset=UTF-8", "Authorization" to "Bearer ${instanceInfo?.access_token}")

    val (_, _, post_res) = Fuel.post(websvc)
            .body(Gson().toJson(mapOf("incomingData" to Gson().toJson(outgoing).toString(),
                    "fieldDefaultData" to Gson().toJson(defaults).toString())))
            .responseString()

    when (post_res) {
        is Result.Failure -> {
            println(post_res.getException())
            //null
        }
        is Result.Success -> {
            println("${outgoing.size}-item upload succeeded.")
            //post_res.get()
        }
    }
}

private fun authenticate(configParams: Map<String, String>): SfdcResponse? {
    val signer = RSASigner.newSHA256Signer(loadResource("sfdc_server.key"))

    val jwt = JWT().setIssuer(configParams["client_id"])
            .setSubject(configParams["endpoint_user"])
            .setAudience(configParams["service_endpoint"])
            .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60))

    val encodedJWT = JWT.getEncoder().encode(jwt, signer)

    val query = "grant_type=${URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", "utf-8")}&assertion=${URLEncoder.encode(encodedJWT, "utf-8")}"

    val tmp_url = "${configParams["token_url"]}?$query"

    val (_, _, result) = tmp_url.httpPost().responseString()
    val instanceInfo = when (result) {
        is Result.Failure -> {
            result.getException()
            null
        }
        is Result.Success -> {
            Gson().fromJson(result.get(), SfdcResponse::class.java)
        }
    }
    return instanceInfo
}

private fun loadResource(resource: String): String =
        try {
            object {}.javaClass.getResource(resource)
                    .readText(Charsets.UTF_8)
        } catch (all: Exception) {
            throw RuntimeException("Failed to load resource=$resource!", all)
        }
