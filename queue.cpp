#include "queue.h"
#include <stdlib.h>

// function to create a queue of given capacity. 
// It initializes size of queue as 0
PQUEUE createQueue(unsigned capacity)
{
	PQUEUE queue = (PQUEUE) malloc(sizeof(QUEUE));
	queue->capacity = capacity;
	queue->front = queue->size = 0;
	queue->rear = capacity - 1;  // This is important, see the enqueue
	queue->data_arr = (unsigned char**)malloc(queue->capacity * sizeof(char*));
	queue->pkt_size_arr = (unsigned int*)malloc(queue->capacity * sizeof(int));
	return queue;
}

// Queue is full when size becomes equal to the capacity 
bool is_queue_full(PQUEUE queue)
{
	return (queue->size == queue->capacity);
}

// Queue is empty when size is 0
bool is_queue_empty(PQUEUE queue)
{
	return (queue->size == 0);
}

bool enqueue(PQUEUE queue, unsigned char *item, unsigned int pkt_size)
{
	if (is_queue_full(queue))
		return false;
	queue->rear = (queue->rear + 1) % queue->capacity;
	queue->data_arr[queue->rear] = item;
	queue->pkt_size_arr[queue->rear] = pkt_size;
	queue->size = queue->size + 1;
	return true;
}

Pqueue_Entry dequeue(PQUEUE queue)
{
	if (is_queue_empty(queue))
		return nullptr;
	unsigned char *item = queue->data_arr[queue->front];
	
	Pqueue_Entry entry = (Pqueue_Entry)malloc(sizeof(QueueEntry));
	entry->pkt_size = queue->pkt_size_arr[queue->front];
	entry->data = queue->data_arr[queue->front];
	queue->front = (queue->front + 1) % queue->capacity;
	queue->size = queue->size - 1;
	return entry;
}

unsigned char* front(PQUEUE queue)
{
	if (is_queue_empty(queue))
		return nullptr;
	return queue->data_arr[queue->front];
}

unsigned char* rear(PQUEUE queue)
{
	if (is_queue_empty(queue))
		return nullptr;
	return queue->data_arr[queue->rear];
}
