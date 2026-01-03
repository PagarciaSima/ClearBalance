import { Component, Input, OnChanges, SimpleChanges, AfterViewInit } from '@angular/core';
import * as L from 'leaflet';
import { Customer } from 'src/app/interface/customer';
import { HttpClient } from '@angular/common/http';

// Fix Leaflet marker icon and shadow image paths
const DefaultIcon = L.icon({
  iconUrl: 'assets/img/marker-icon.png',
  shadowUrl: 'assets/img/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41]
});
L.Marker.prototype.options.icon = DefaultIcon;

@Component({
  selector: 'app-customers-map',
  templateUrl: './customers-map.component.html',
  styleUrls: ['./customers-map.component.css']
})
export class CustomersMapComponent implements OnChanges, AfterViewInit {
  @Input() customers: Customer[] | undefined;
  private map: L.Map | null = null;
  private markers: L.LayerGroup = L.layerGroup();

  constructor(private http: HttpClient) {}

  /**
   * Initializes the Leaflet map after the view is initialized.
   */
  ngAfterViewInit(): void {
    this.initMap();
    this.updateMarkers();
  }

  /**
   * Handles changes to input properties.
   * @param changes The changed properties
   */
  ngOnChanges(changes: SimpleChanges): void {
    if (changes['customers'] && this.map) {
      this.updateMarkers();
    }
  }

  /**
   * Initializes the Leaflet map with a global view and adds the marker layer.
   */
  private initMap(): void {
    if (this.map) return;
    this.map = L.map('customers-map', {
      center: [30, 0], // global view
      zoom: 2,
      zoomControl: true
    });
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors'
    }).addTo(this.map);
    this.markers.addTo(this.map);
  }

  /**
   * Updates the markers on the map based on the provided customers.
   */
  private async updateMarkers(): Promise<void> {
    this.markers.clearLayers();
    if (!this.customers || this.customers.length === 0) return;
    // Add a delay between geocoding requests to avoid Nominatim rate limits
    for (const customer of this.customers) {
      if (customer && customer.address) {
        // eslint-disable-next-line no-await-in-loop
        const coords = await this.geocodeAddress(customer.address);
        if (coords) {
          const marker = L.marker(coords).bindPopup(
            `<b>${customer.name}</b><br>${customer.address}`
          );
          marker.addTo(this.markers);
        }
        // No delay between requests for faster loading
      }
    }
  }

  /**
   * Geocodes an address using Nominatim (OpenStreetMap)
   * @param address The address string
   * @returns Promise with [lat, lon] or null
   */
  private geocodeAddress(address: string): Promise<[number, number] | null> {
    // Add &limit=1 to ensure only one result is returned
    const url = `https://nominatim.openstreetmap.org/search?format=json&limit=1&q=${encodeURIComponent(address)}`;
    return this.http.get<any[]>(url).toPromise().then(results => {
      if (Array.isArray(results) && results.length > 0 && results[0].lat && results[0].lon) {
        const lat = Number(results[0].lat);
        const lon = Number(results[0].lon);
        if (!isNaN(lat) && !isNaN(lon)) {
          return [lat, lon] as [number, number];
        }
      }
      return null;
    }).catch(() => null);
  }
}
