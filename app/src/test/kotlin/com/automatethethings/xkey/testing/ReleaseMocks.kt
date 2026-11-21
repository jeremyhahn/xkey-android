package com.automatethethings.xkey.testing

import io.mockk.clearAllMocks
import org.junit.rules.ExternalResource

/**
 * Releases what MockK holds for the test that just ran, so the unit-test JVM
 * does not carry it into every later test.
 *
 * MockK records every call on a mock as an `Invocation` that keeps the mock
 * itself, the arguments (a suspend call's continuation, and through it the
 * whole coroutine frame) and a captured stack trace. For a mock of a final or
 * Android class (an inline mock), the agent's handler table keys the mock
 * weakly but its value reaches the recorded calls and stubbed answers, and so
 * the mock again: neither is ever collected. A test that drives thousands of
 * calls through such mocks then keeps all of them, stack traces included, for
 * the rest of the run, and the suite's single test JVM ran out of heap.
 *
 * [clearAllMocks] drops every mock's recorded calls and answers, which cuts
 * that cycle. Any test class that drives many calls through MockK mocks takes
 * this rule:
 *
 * ```
 * @get:Rule
 * val releaseMocks = ReleaseMocks()
 * ```
 *
 * It runs after the class's own `@After` methods, so a teardown that still
 * stubs or verifies sees its mocks intact.
 */
class ReleaseMocks : ExternalResource() {
    override fun after() = clearAllMocks()
}
