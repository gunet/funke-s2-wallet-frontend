// Target characteristic UUIDs
const TARGET_WRITE_CHARACTERISTIC_UUID = "00000005-a123-48ce-896b-4c76973373e6";
const TARGET_NOTIFY_CHARACTERISTIC_UUID = "00000007-a123-48ce-896b-4c76973373e6";


export async function startBLE(uuidInput) {
	return new Promise(async (resolve, reject) => {
		let fullRequest = '';
		try {
			const uuid = uuidInput || "00179c7a-eec6-4f88-8646-045fda9ac4d8";
			console.log(`Setting UUID to: ${uuid}`);
	
			// Request a BLE device
			/* @ts-ignore */
			const device = await navigator.bluetooth.requestDevice({
				acceptAllDevices: false,
				filters: [{ services: [uuid] }]
			});
	
			console.log(`Device selected: ${device.name}`);
	
			// Connect to the GATT server
			const server = await device.gatt.connect();
			console.log("Connected to GATT server");
	
			// Get the primary service
			const service = await server.getPrimaryService(uuid);
			console.log(`Primary service found: ${service.uuid}`);
	
			// List and interact with characteristics
			try {
				const characteristics = await service.getCharacteristics();
				let writeCharacteristic = null;
		
				for (const characteristic of characteristics) {
					console.log(`Found characteristic: ${characteristic.uuid}`);
		
					// Check if it's the write characteristic
					if (characteristic.uuid === TARGET_WRITE_CHARACTERISTIC_UUID) {
						console.log(`Target write characteristic found: ${TARGET_WRITE_CHARACTERISTIC_UUID}`);
						writeCharacteristic = characteristic;
					}
		
					// Check if it's the notify characteristic
					if (characteristic.uuid === TARGET_NOTIFY_CHARACTERISTIC_UUID) {
						console.log(`Target notify characteristic found: ${TARGET_NOTIFY_CHARACTERISTIC_UUID}`);
						try {
							if (characteristic.properties.notify) {
								console.log(`Subscribing to notifications for: ${characteristic.uuid}`);
								characteristic.addEventListener("characteristicvaluechanged", (event) => {
									console.log("Inside the characteristic LISTENER YYYYYYYYYYYY");
									const value = event.target.value;
									const receivedData = new Uint8Array(value.buffer);
									console.log(`Notification received: ${Array.from(receivedData).map(b => b.toString(16).padStart(2, '0')).join('')}`);
									const firstByte = Array.from(receivedData)[0];
									console.log(`First byte: ${Array.from(receivedData)[0]}`);
									fullRequest += Array.from(receivedData.subarray(1)).map(b => b.toString(16).padStart(2, '0')).join('')
									if (firstByte === 0) {
										resolve(fullRequest);
									}
								});
								await characteristic.startNotifications();
								console.log("Successfully subscribed to notifications.");
							} else {
								console.log("Characteristic does not support notifications.");
							}
						} catch (error) {
							console.error("Error subscribing to notifications:", error);
						}
					}
				}
		
				// Write to the write characteristic if available
				if (writeCharacteristic) {
					try {
						const value = new Uint8Array([0x01]); // Data to write
						await writeCharacteristic.writeValue(value);
						console.log(`Successfully wrote ${value} to characteristic: ${writeCharacteristic.uuid}`);
					} catch (error) {
						console.error("Error writing to characteristic:", error);
					}
				} else {
					console.log("Target write characteristic not found.");
				}
			} catch (error) {
				console.error("Error listing characteristics:", error);
			}
		} catch (error) {
			console.error("Error during BLE communication:", error);
		}
	})
	
}

async function listCharacteristics(service) {

}

async function writeToCharacteristic(characteristic) {

}

async function subscribeToNotifications(characteristic) {

}