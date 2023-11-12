package com.kotcrab.ghidra.rest

import com.kotcrab.ghidra.rest.mapper.BookmarkMapper
import com.kotcrab.ghidra.rest.mapper.DataTypeMapper
import com.kotcrab.ghidra.rest.mapper.RelocationMapper
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
import ghidra.program.model.listing.Program
import io.ktor.serialization.jackson.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.*
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

  private val bookmarkMapper = BookmarkMapper()
  private val dataTypeMapper = DataTypeMapper()
  private val relocationMapper = RelocationMapper()
  private val symbolMapper = SymbolMapper()

  public override fun init() {
    super.init()
    startServer = createAction("Start Rest API Server", ::startServer)
    stopServer = createAction("Stop Rest API Server", ::stopServer)
  }

  override fun dispose() {
    super.dispose()
    stopServer()
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

  private fun startServer() {
    server = createServer().also { it.start() }
  }

  private fun stopServer() {
    server?.stop()
    server = null
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
        get("/bookmarks") {
          withErrorLogging {
            ensureProgramLoaded()
            val bookmarks = bookmarkMapper.map(currentProgram.bookmarkManager)
            call.respond(mapOf("bookmarks" to bookmarks))
          }
        }
        get("/relocations") {
          withErrorLogging {
            ensureProgramLoaded()
            val relocations = relocationMapper.map(currentProgram.relocationTable)
            call.respond(mapOf("relocations" to relocations))
          }
        }
        get("/symbols") {
          withErrorLogging {
            ensureProgramLoaded()
            val symbols = symbolMapper.map(currentProgram.symbolTable, currentProgram.listing)
            call.respond(mapOf("symbols" to symbols))
          }
        }
        get("/types") {
          withErrorLogging {
            ensureProgramLoaded()
            val types = dataTypeMapper.map(currentProgram.dataTypeManager)
            call.respond(mapOf("types" to types))
          }
        }
      }
    }
  }

  private fun ensureProgramLoaded() {
    if (currentProgram == null) {
      throw BadRequestException("No program is loaded")
    }
  }

  private inline fun withErrorLogging(block: () -> Unit) {
    runCatching { block() }
      .onFailure { logger.error("Error in $PLUGIN_NAME: ${it.message}", it) }
      .getOrThrow()
  }
}
