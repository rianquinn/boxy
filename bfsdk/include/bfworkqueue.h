/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BFWORKQUEUE_H
#define BFWORKQUEUE_H

#include <bftypes.h>
#include <bfconstants.h>

#define WORKQUEUE_SUCCESS 0
#define WORKQUEUE_INVALID_ARGS -1
#define WORKQUEUE_FULL -2

/**
 * @struct workqueue_header
 *
 * Work Queue
 *
 * https://embeddedartistry.com/blog/2017/4/6/circular-buffers-in-cc#c-implementation
 *
 * Handles:
 * The implementation above defines a single, containing object (or handle) that
 * stores the information about the buffer that is used. We cannot do that here
 * as all of the information that is used to define the queue must be stored in
 * a single page (or multiple pages) that can then be shared between the VM and
 * the hypervisor, or between a VM and another VM. The location of the buffer
 * will be different in virtual memory between each entity touching the queue.
 * To support this, we create two structures:
 * - workqueue
 * - workqueue_header
 *
 * workqueue:
 * The workqueue is the main structure that is passed to all of the APIs, and
 * it is local to the hypervisor or VM that is touching the queue, which means
 * that the virtual addresses make sense to the entity that is touching the
 * queue. A workqueue is created by providing a buffer to the APIs. The queue
 * however is not initialized when creating. This allows the server and client
 * to create the queue from a single, shared buffer no matter what the state of
 * the buffer actually is. The server can then initialize the queue to set up
 * its initial state (something the client will not do as only one side should
 * initialize the queue).
 *
 * workqueue_header:
 * The workqueue header is a header that takes up the first part of the buffer
 * that is shared between the entities that are using the queue. Unlike the
 * workqueue above, the information about the state of the queue is stored
 * in the buffer itself to ensure that it is properly shared between the
 * entities that are using the queue. No virtual address information is stored
 * in this header (which is stored in the workqueue itself) to ensure that the
 * information in the shared buffer makes sense no matter who is looking at it.
 *
 * Error Handling:
 * Instead of using asserts, which would not be portable as this code needs to
 * execute in multiple different kernels and the hypervisor itself, we return
 * error codes when the contract was violated. Like asserts, this implementation
 * is not perfect as the user could easily provide corrupt data to these APIs
 * since pointers have to be used (we need to support C) and as such, bad things
 * could still happen if the contract is really violated badly.
 *
 * Thread Safety:
 * This implementation must be thread safe. The problem is, we cannot use the
 * platform_xxx functions for mutexes as those functions assume that the
 * mutex itself is defined by the platform, and in this case, more than one
 * platform (i.e more than one OS) will need to interface with the queue
 * simultaneously, which means the mutex implementation must be cross-platform.
 * To support this, we require the user to implement atomic functions which we
 * will use to implement our own, cross-platform mutex for the queue.
 *
 * Core Guideline Compliance:
 * Although this code is written in C to support different kernels, we attempt
 * to adhere to the C++ Core Guidelines as much as possible, including
 * performing contract and bounds checks on all public APIs. To ensure this
 * code executes as fast as possible we include branch prediction hints.
 */
struct workqueue_header {
    uint32_t head;
    uint32_t tail;
    uint32_t size;
    uint32_t lock;
    uint32_t full;
};

struct workqueue {
    struct workqueue_header *hdr;
    uint8_t *data;
    uint32_t size;
};

#define assert_queue(a)                                                         \
    if (bfunlikely(a == nullptr)) {                                             \
        return WORKQUEUE_INVALID_ARGS;                                          \
    }                                                                           \
    if (bfunlikely(a->hdr == nullptr)) {                                        \
        return WORKQUEUE_INVALID_ARGS;                                          \
    }

int
workqueue_create(
    struct workqueue *queue, uint8_t *data, uint32_t size)
{
    if (bfunlikely(queue == nullptr)) {
        return WORKQUEUE_INVALID_ARGS;
    }

    queue->hdr = nullptr;
    queue->data = nullptr;
    queue->size = 0;

    if (bfunlikely(data == nullptr)) {
        return WORKQUEUE_INVALID_ARGS;
    }

    if (size < BAREFLANK_PAGE_SIZE) {
        return WORKQUEUE_INVALID_ARGS;
    }

    if ((size & (BAREFLANK_PAGE_SIZE - 1)) != 0) {
        return WORKQUEUE_INVALID_ARGS;
    }

    queue->hdr = bfrcast(struct workqueue_header *, data);
    queue->data = data + sizeof(struct workqueue_header);
    queue->size = size - sizeof(struct workqueue_header);

    return WORKQUEUE_SUCCESS;
}

int
workqueue_init(
    struct workqueue *queue)
{
    assert_queue(queue);

    queue->hdr->head = 0;
    queue->hdr->tail = 0;
    queue->hdr->size = queue->size;
    queue->hdr->lock = 0;
    queue->hdr->full = 0;

    return WORKQUEUE_SUCCESS;
}

int
workqueue_empty(const struct workqueue *queue)
{
    assert_queue(queue);
    return (queue->hdr->full == 0) && (queue->hdr->head == queue->hdr->tail);
}

int
workqueue_full(const struct workqueue *queue)
{
    assert_queue(queue);
    return queue->hdr->full != 0;
}

int
workqueue_capacity(const struct workqueue *queue)
{
    assert_queue(queue);
    return queue->hdr->size;
}

int
workqueue_size(const struct workqueue *queue)
{
    assert_queue(queue);

    if (queue->hdr->full != 0) {
        return queue->hdr->size;
    }

    if (queue->hdr->head >= queue->hdr->tail) {
        return queue->hdr->head - queue->hdr->tail;
    }
    else {
        return queue->hdr->size + queue->hdr->head - queue->hdr->tail;
    }
}

int
workqueue_push(
    struct workqueue *queue, const void *data, uint32_t size)
{

}

int
workqueue_pop(
    struct workqueue *queue, void *data, uint32_t size)
{

}


#endif
