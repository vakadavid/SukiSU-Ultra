package com.sukisu.ultra.ui.screen

import android.annotation.SuppressLint
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.R
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.foundation.layout.Column
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import com.sukisu.ultra.ui.util.retrieveSulogLogs
import com.sukisu.ultra.ui.util.streamFile

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Destination<RootGraph>
fun SulogScreen(navigator: DestinationsNavigator) {
    val scrollBehavior = TopAppBarDefaults.enterAlwaysScrollBehavior(rememberTopAppBarState())
    data class SulogEntry(val uptime: Int, val uid: Int, val sym: Char, val raw: String)
    var entries by remember { mutableStateOf(listOf<SulogEntry>()) }

    LaunchedEffect(true) {
        val regex = Regex("""uptime_s=(\d+)\s+uid=(\d+)\s+sym=(.)""")
        while (isActive) {
            // trigger kernel dump and give it a moment
            retrieveSulogLogs()
            delay(1000)

            // stream file (incremental)
            val streamed = streamFile("/data/adb/ksu/log/sulog.log")
            val allLines = if (streamed.isEmpty()) emptyList() else streamed.takeLast(2000)

            // parse and dedupe new lines, keep newest-first merge with existing entries
            val parsed = mutableListOf<SulogEntry>()
            val seen = LinkedHashSet<String>()
            for (ln in allLines) {
                val lineTrim = ln.trim()
                if (lineTrim.isEmpty()) continue
                val m = regex.find(lineTrim)
                val entry = if (m != null) {
                    val uptime = m.groupValues[1].toIntOrNull() ?: 0
                    val uid = m.groupValues[2].toIntOrNull() ?: 0
                    val sym = m.groupValues[3].firstOrNull() ?: '?'
                    if (uptime == 0 && uid == 0 && sym == '?') null else SulogEntry(uptime, uid, sym, lineTrim)
                } else {
                    SulogEntry(0, 0, '?', lineTrim)
                }
                if (entry != null) {
                    val key = "${entry.uptime}|${entry.uid}|${entry.sym}|${entry.raw}"
                    if (seen.add(key)) parsed.add(entry)
                }
            }

            // merge: prefer parsed (new) over existing, preserve newest-first order, cap size
            val map = linkedMapOf<String, SulogEntry>()
            parsed.forEach { map["${it.uptime}|${it.uid}|${it.sym}|${it.raw}"] = it }
            entries.forEach { key -> 
                val k = "${key.uptime}|${key.uid}|${key.sym}|${key.raw}"
                if (!map.containsKey(k)) map[k] = key
            }
            val combined = map.values.toList()
            entries = combined
            
            delay(4000)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.log_viewer_title)) },
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = { navigator.popBackStack() }) {
                        val layoutDirection = LocalLayoutDirection.current
                        Icon(
                            modifier = Modifier.graphicsLayer {
                                if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                            },
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = null,
                        )
                    }
                }
            )
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 12.dp),
            contentPadding = innerPadding,
        ) {
            // default sort: type priority (i > x > $) then newest-first within each type
            val priority = { c: Char ->
                when (c) {
                    'i' -> 0
                    'x' -> 1
                    '$' -> 2
                    else -> 3
                }
            }
            val displayed = entries.sortedWith(compareBy({ priority(it.sym) }, { -it.uptime }))
            items(displayed) { e ->
                Card(modifier = Modifier.padding(vertical = 6.dp)) {
                    Column(modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp)) {
                        val bgDesc = when (e.sym) {
                            '$' -> stringResource(id = R.string.sulog_blocked_label)
                            'x' -> stringResource(id = R.string.sulog_allowed_label)
                            'i' -> stringResource(id = R.string.sulog_ioctl_label)
                            else -> stringResource(id = R.string.sulog_other_label)
                        }
                        Text(text = "$bgDesc • uid=${e.uid} • uptime=${formatDuration(e.uptime)}")
                    }
                }
            }
        }
    }
}

@SuppressLint("DefaultLocale")
private fun formatDuration(sec: Int): String {
    if (sec <= 0) return "0s"
    val h = sec / 3600
    val m = (sec % 3600) / 60
    val s = sec % 60
    return if (h > 0) String.format("%dh%02dm%02ds", h, m, s) else if (m > 0) String.format("%dm%02ds", m, s) else String.format("%ds", s)
}
