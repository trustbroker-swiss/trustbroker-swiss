/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 * 
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>. 
 */

package swiss.trustbroker.common.tracing;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicLong;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DefaultRequestContextFactory implements RequestContextFactory {

	@SuppressWarnings("java:S5164") // we keep the empty stack per thread
	private static final ThreadLocal<Deque<RequestContext>> contextDeque = new ThreadLocal<>();

	private final AtomicLong reqCounter = new AtomicLong();

	public RequestContext create(String calledObject, String calledMethod) {
		return create(
				calledObject,
				calledMethod,
				createInitialTransferId(),
				null,
				null
		);
	}

	@Override
	public RequestContext create(String calledObject, String calledMethod, String transferId, String principal,	String clientId) {
		return create(calledObject, calledMethod, transferId, principal, clientId, null, null);
	}

	@Override
	public RequestContext create(String calledObject, String calledMethod, String transferId, String principal, String clientId,
			Object fullRequestContext, Object fullResponseContext) {
		return create(calledObject, calledMethod, transferId, principal, clientId, new AtomicLong(),
				fullRequestContext, fullResponseContext);
	}

	@Override
	public RequestContext create(String calledObject, String calledMethod, RequestContext context) {
		return create(calledObject, calledMethod, context.getTransferId(), context.getPrincipal(), context.getClientId(),
				context.getFanOutRequestCounter(), null, null);
	}

	@SuppressWarnings("java:S107")
	private RequestContext create(String calledObject, String calledMethod, String transferId, String principal, String clientId,
			AtomicLong fanOutRequestCounter, Object fullRequestContext, Object fullResponseContext) {
		// make sure we can track the request, also when a logInitialEnter in a batch job did not detect an incoming one
		if (transferId == null) {
			transferId = createInitialTransferId();
		}
		var rc = DefaultRequestContext
				.builder()
				.calledObject(calledObject)
				.calledMethod(calledMethod)
				.clientId(clientId)
				.transferId(transferId)
				.principal(principal)
				.fanOutRequestCounter(fanOutRequestCounter)
				.fullRequestContext(fullRequestContext)
				.fullResponseContext(fullResponseContext)
				.build();
		setRequestContext(rc);
		return rc;
	}

	public RequestContext extendTransferId(String obj, String mth) {
		RequestContext rc = getNextTransferId(obj, mth);
		setRequestContext(rc);
		return rc;
	}

	public RequestContext getNextTransferId(String calledObject, String calledMethod) {
		var rc = getRequestContext();
		if (rc == null) {
			throw new IllegalStateException("RequestContext missing in current thread due to missing logIntialEnter!");
		}
		var id = rc.getTransferId();
		var principal = rc.getPrincipal();
		var clientId = rc.getClientId();
		var fanOutRequestCounter = rc.getFanOutRequestCounter();
		return DefaultRequestContext
				.builder()
				.calledObject(calledObject)
				.calledMethod(calledMethod)
				.clientId(clientId)
				.transferId(id + "-" + createRequestGUID8())
				.principal(principal)
				.fanOutRequestCounter(fanOutRequestCounter)
				.build();
	}

	public RequestContext getRequestContext() {
		RequestContext requestContext = null;
		var stack = getContextDeque();
		if (stack.isEmpty()) {
			// legal state of OpTracing
			log.debug("Context stack for this thread is still empty, return null");
		}
		else {
			requestContext = stack.peek();
		}
		return requestContext;
	}

	public void pushRequestContext(RequestContext rc) {
		getContextDeque().push(rc);
	}

	public void delete() {
		var stack = contextDeque.get();
		stack.pop();
	}

	private static Deque<RequestContext> getContextDeque() {
		var stack = contextDeque.get();
		if (stack == null) {
			stack = new ArrayDeque<>();
			contextDeque.set(stack);
		}
		return stack;
	}

	private String createRequestGUID8() {
		var id = reqCounter.getAndIncrement();
		return String.format("%08x", id);
	}

	public void setRequestContext(RequestContext ctx) {
		pushRequestContext(ctx);
	}

	public String createInitialTransferId() {
		return "00000000." + OpTraceUtil.PID_HEX_4 + "." + OpTraceUtil.HOST_IP_HEX_8 + "." + createRequestGUID8();
	}

}

