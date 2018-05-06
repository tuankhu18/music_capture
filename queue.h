#pragma once
#define MAX_QUEUE 4096

typedef struct Queue
{
	int front, rear, size;
	unsigned capacity;
	unsigned char **data_arr;
	unsigned int *pkt_size_arr;
} QUEUE, *PQUEUE;

typedef struct QueueEntry {
	unsigned char *data;
	unsigned int pkt_size;
} QueueEntry, *Pqueue_Entry;

Pqueue_Entry dequeue(PQUEUE p_queue);
bool enqueue(PQUEUE p_queue, unsigned char *data, unsigned int);
unsigned char* front(PQUEUE p_queue);
unsigned char* rear(PQUEUE p_queue);
bool is_queue_empty(PQUEUE p_queue);
bool is_queue_full(PQUEUE p_queue);
PQUEUE createQueue(unsigned capacity);
