#include "sysinclude.h"
#include <queue>
#include <iostream>
using namespace std;

extern void SendFRAMEPacket(unsigned char* pData, unsigned int len);
#define WINDOW_SIZE_STOP_WAIT 1
#define WINDOW_SIZE_BACK_N_FRAME 4

#define DATA_BUFFER_SCALE 255

#ifndef  FRAME_TYPE
#define FRAME_TYPE
#define DATA 0
#define ACK 1
#define NAK 2
#endif

#define uint_t unsigned int
#define uchar_t unsigned char

typedef struct frame_head {
	uint_t type;
	uint_t seq_num;
	uint_t ack;
	uchar_t data[DATA_BUFFER_SCALE];
};

typedef struct frame {
	frame_head head;
	uint_t size;
};

queue<frame> frame_to_send_queue;
queue<frame> backup_buffer_queue;
frame frame_to_send;
uint_t sent_buf_num = 0;

inline uint_t reverse(const uint_t data) {
    // Reverse the word order
	return(((data & 0xff000000) >> 24) | ((data & 0xff0000) >> 8) | ((data & 0xff00) << 8) | ((data & 0xff) << 24));
}


/*
* 停等协议测试函数
*/
int stud_slide_window_stop_and_wait(char* pBuffer, int bufferSize, UINT8 messageType) {
	switch (messageType) {
	case MSG_TYPE_TIMEOUT:
		frame_to_send = backup_buffer_queue.front();
		SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
		return 0;
	case MSG_TYPE_SEND:
		memcpy(&frame_to_send, pBuffer, sizeof(frame));
		frame_to_send.size = bufferSize;
		frame_to_send_queue.push(frame_to_send);
		if (sent_buf_num < WINDOW_SIZE_STOP_WAIT) {
			frame_to_send = frame_to_send_queue.front();
			frame_to_send_queue.pop();
			backup_buffer_queue.push(frame_to_send);
			SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
			sent_buf_num++;	
		}
		return 0;
	case MSG_TYPE_RECEIVE:
		backup_buffer_queue.pop();
		sent_buf_num -= 1;
		if (!frame_to_send_queue.empty()) {
			frame_to_send = frame_to_send_queue.front();
			frame_to_send_queue.pop();
			backup_buffer_queue.push(frame_to_send);
			SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
			sent_buf_num++;
		}
		return 0;
	DEFAULT:
		cerr << "Undefined Message Type." << endl;
		return -1;
	}
}

/*
* 回退帧测试函数n
*/
int stud_slide_window_back_n_frame(char* pBuffer, int bufferSize, UINT8 messageType) {
	switch (messageType) {
	case MSG_TYPE_TIMEOUT:
		for (int i = 0; i < sent_buf_num; i++) {
			frame_to_send = backup_buffer_queue.front();
			backup_buffer_queue.pop();
			backup_buffer_queue.push(frame_to_send);
			SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
		}
		return 0;
	case MSG_TYPE_SEND:
		memcpy(&frame_to_send, pBuffer, sizeof(frame));
		frame_to_send.size = bufferSize;
		frame_to_send_queue.push(frame_to_send);
		while (sent_buf_num < WINDOW_SIZE_BACK_N_FRAME && !frame_to_send_queue.empty()) {
			frame_to_send = frame_to_send_queue.front();
			frame_to_send_queue.pop();
			backup_buffer_queue.push(frame_to_send);
			SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
			sent_buf_num++;
		}
		return 0;
	case MSG_TYPE_RECEIVE:
		int stop_ack = reverse((((frame*)pBuffer)->head).ack);
		int type = reverse((((frame*)pBuffer)->head).type);
		if (type != ACK) {
			// do nothing
			return 0;
		}

		while (reverse((backup_buffer_queue.front()).head.seq_num) <= stop_ack) {
			backup_buffer_queue.pop();
			sent_buf_num--;
			if (sent_buf_num < WINDOW_SIZE_BACK_N_FRAME && !frame_to_send_queue.empty()) {
				frame_to_send = frame_to_send_queue.front();
				frame_to_send_queue.pop();
				backup_buffer_queue.push(frame_to_send);
				SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
				sent_buf_num++;
			}
		}
		return 0;
	DEFAULT:
		cerr << "Undefined Message Type." << endl;
		return -1;
	}
}

/*
* 选择性重传测试函数
*/
int stud_slide_window_choice_frame_resend(char* pBuffer, int bufferSize, UINT8 messageType) {
	switch (messageType) {
	case MSG_TYPE_SEND:
		memcpy(&frame_to_send, pBuffer, sizeof(frame));
		frame_to_send.size = bufferSize;
		frame_to_send_queue.push(frame_to_send);
		while (sent_buf_num < WINDOW_SIZE_BACK_N_FRAME && !frame_to_send_queue.empty()) {
			frame_to_send = frame_to_send_queue.front();
			frame_to_send_queue.pop();
			backup_buffer_queue.push(frame_to_send);
			SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
			sent_buf_num++;
		}
		return 0;
	case MSG_TYPE_RECEIVE:
		int stop_ack = reverse((((frame*)pBuffer)->head).ack);
		int type = reverse((((frame*)pBuffer)->head).type);
		if (type == ACK) {
			while (reverse((backup_buffer_queue.front()).head.seq_num) <= stop_ack) {
				backup_buffer_queue.pop();
				sent_buf_num--;
				if (sent_buf_num < WINDOW_SIZE_BACK_N_FRAME && !frame_to_send_queue.empty()) {
					frame_to_send = frame_to_send_queue.front();
					frame_to_send_queue.pop();
					backup_buffer_queue.push(frame_to_send);
					SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
					sent_buf_num++;
				}
			}
		}
		else if (type == NAK) {
			while (reverse((backup_buffer_queue.front()).head.seq_num) < stop_ack) {
				backup_buffer_queue.pop();
				sent_buf_num--;
			}
			frame_to_send = backup_buffer_queue.front();
			SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
			while (sent_buf_num < WINDOW_SIZE_BACK_N_FRAME && !frame_to_send_queue.
				empty()) {
				frame_to_send = frame_to_send_queue.front();
				frame_to_send_queue.pop();
				backup_buffer_queue.push(frame_to_send);
				SendFRAMEPacket((unsigned char *)&frame_to_send, frame_to_send.size);
				sent_buf_num++;
			}
		}
		return 0;
	DEFAULT:
		cerr << "Undefined Message Type." << endl;
		return -1;
	}
}