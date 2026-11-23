package com.automatethethings.xkey.media

import android.app.Application
import android.os.ParcelFileDescriptor
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class PipeProbeTest {
    @Test
    fun probe() {
        val (r, w) = ParcelFileDescriptor.createPipe()
        println("PROBE r=${r.javaClass} fd=${r.fileDescriptor} valid=${r.fileDescriptor.valid()}")
        FileOutputStream(w.fileDescriptor).write(byteArrayOf(1, 2, 3))
        val ex = Executors.newSingleThreadExecutor()
        val stream = FileInputStream(r.fileDescriptor)
        val f = ex.submit<String> {
            val buf = ByteArray(8)
            val n1 = stream.read(buf)
            val n2 = try { stream.read(buf) } catch (e: Exception) { -100 }
            "n1=$n1 n2=$n2"
        }
        Thread.sleep(500)
        println("PROBE done-before-close=${f.isDone}")
        r.close()
        println("PROBE after pfd close: " + try { f.get(2, TimeUnit.SECONDS) } catch (e: Exception) { "timeout $e" })
        // channel variant
        val (r2, w2) = ParcelFileDescriptor.createPipe()
        FileOutputStream(w2.fileDescriptor).write(byteArrayOf(1, 2, 3))
        val ch = FileInputStream(r2.fileDescriptor).channel
        val f2 = ex.submit<String> {
            val b = ByteBuffer.allocate(8)
            val n1 = ch.read(b); b.clear()
            val n2 = try { ch.read(b) } catch (e: Exception) { -200 }
            "n1=$n1 n2=$n2"
        }
        Thread.sleep(500)
        println("PROBE ch done-before-close=${f2.isDone}")
        ch.close()
        println("PROBE after channel close: " + try { f2.get(2, TimeUnit.SECONDS) } catch (e: Exception) { "timeout $e" })
        w.close(); w2.close(); r2.close()
        ex.shutdownNow()
    }
}
