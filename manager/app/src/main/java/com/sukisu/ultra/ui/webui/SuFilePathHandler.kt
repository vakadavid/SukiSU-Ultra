package com.sukisu.ultra.ui.webui

import android.util.Log
import android.webkit.WebResourceResponse
import androidx.annotation.WorkerThread
import androidx.webkit.WebViewAssetLoader
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.io.SuFile
import com.topjohnwu.superuser.io.SuFileInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.zip.GZIPInputStream

class SuFilePathHandler(
    directory: File,
    private val mShell: Shell
) : WebViewAssetLoader.PathHandler {

    private val mDirectory: File

    init {
        try {
            mDirectory = File(getCanonicalDirPath(directory))
            if (!isAllowedInternalStorageDir()) {
                throw IllegalArgumentException(
                    "The given directory \"$directory\" doesn't exist under an allowed app internal storage directory"
                )
            }
        } catch (e: IOException) {
            throw IllegalArgumentException(
                "Failed to resolve the canonical path for the given directory: ${directory.path}",
                e
            )
        }
    }

    private fun isAllowedInternalStorageDir(): Boolean {
        return try {
            val dir = getCanonicalDirPath(mDirectory)
            FORBIDDEN_DATA_DIRS.none { dir.startsWith(it) }
        } catch (_: IOException) {
            false
        }
    }

    @WorkerThread
    override fun handle(path: String): WebResourceResponse {
        try {
            val file = getCanonicalFileIfChild(mDirectory, path)
            if (file != null) {
                val inputStream = openFile(file, mShell)
                val mimeType = guessMimeType(path)
                return WebResourceResponse(mimeType, null, inputStream)
            } else {
                Log.e(
                    TAG,
                    "The requested file: $path is outside the mounted directory: $mDirectory"
                )
            }
        } catch (e: IOException) {
            Log.e(TAG, "Error opening the requested path: $path", e)
        }
        return WebResourceResponse(null, null, null)
    }

    companion object {
        private const val TAG = "SuFilePathHandler"
        const val DEFAULT_MIME_TYPE = "text/plain"

        private val FORBIDDEN_DATA_DIRS = arrayOf("/data/data", "/data/system")

        fun getCanonicalDirPath(file: File): String {
            val canonicalPath = file.canonicalPath
            return if (!canonicalPath.endsWith("/")) "$canonicalPath/" else canonicalPath
        }

        fun getCanonicalFileIfChild(parent: File, child: String): File? {
            return try {
                val parentCanonicalPath = getCanonicalDirPath(parent)
                val childCanonicalPath = File(parent, child).canonicalPath
                if (childCanonicalPath.startsWith(parentCanonicalPath)) {
                    File(childCanonicalPath)
                } else {
                    null
                }
            } catch (_: IOException) {
                null
            }
        }

        private fun handleSvgzStream(path: String, stream: InputStream): InputStream {
            return if (path.endsWith(".svgz")) GZIPInputStream(stream) else stream
        }

        fun openFile(file: File, shell: Shell): InputStream {
            val suFile = SuFile(file.absolutePath).apply {
                setShell(shell)
            }
            val fis = SuFileInputStream.open(suFile)
            return handleSvgzStream(file.path, fis)
        }

        fun guessMimeType(filePath: String): String {
            return MimeUtil.getMimeFromFileName(filePath) ?: DEFAULT_MIME_TYPE
        }
    }
}
