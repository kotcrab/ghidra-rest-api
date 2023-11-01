package com.kotcrab.ghidra.rest

import com.kotcrab.ghidra.rest.mapper.DataTypeMapper
import com.kotcrab.ghidra.rest.mapper.SymbolMapper
import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import docking.tool.ToolConstants
import ghidra.MiscellaneousPluginPackage
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.apache.logging.log4j.LogManager

@Suppress("unused")
@PluginInfo(
  status = PluginStatus.STABLE,
  packageName = MiscellaneousPluginPackage.NAME,
  category = PluginCategoryNames.MISC,
  shortDescription = "Rest API Plugin",
  description = "This plugin adds read-only REST API to your Ghidra project."
)
class RestApiPlugin(tool: PluginTool) : ProgramPlugin(tool) {
  companion object {
    private const val PLUGIN_NAME = "RestApiPlugin"
    private val logger = LogManager.getLogger(RestApiPlugin::class.java)
  }

  private var startServer: DockingAction? = null
  private var stopServer: DockingAction? = null

  private var server: ApplicationEngine? = null

  private val dataTypeMapper = DataTypeMapper()
  private val symbolMapper = SymbolMapper()

  public override fun init() {
    super.init()
    setupActions()
  }

  private fun setupActions() {
    startServer = createAction("Start Rest API Server") {
      server = createServer().also { it.start() }
    }
    stopServer = createAction("Stop Rest API Server") {
      server?.stop()
      server = null
    }
  }

  private fun createAction(name: String, handler: () -> Unit): DockingAction {
    val action = object : DockingAction(name, PLUGIN_NAME) {
      override fun actionPerformed(context: ActionContext?) {
        handler()
      }
    }
    action.menuBarData = MenuData(arrayOf(ToolConstants.MENU_TOOLS, name))
    action.isEnabled = true
    tool.addAction(action)
    return action
  }

  private fun createServer(): ApplicationEngine {
    return embeddedServer(CIO, port = 18489) {
      configureServer()
    }
  }

  private fun Application.configureServer() {
    install(ContentNegotiation) {
      jackson()
    }
    routing {
      route("/v1") {
        get("/symbols") {
          withErrorLogging {
            val symbols = symbolMapper.map(currentProgram.symbolTable, currentProgram.listing)
            call.respond(mapOf("symbols" to symbols))
          }
        }
        get("/types") {
          withErrorLogging {
            val types = dataTypeMapper.map(currentProgram.dataTypeManager)
            call.respond(mapOf("types" to types))
          }
        }
      }

    }
  }

  private inline fun withErrorLogging(block: () -> Unit) {
    runCatching { block() }
      .onFailure { logger.error("Error in $PLUGIN_NAME: ${it.message}", it) }
      .getOrThrow()
  }
}
